//! Ephemeral least-authority loopback operations dashboard.

use super::{CliError, authorized, load_connection, valid_memory_workspace_identity};
use axum::{
    Json, Router,
    extract::{
        DefaultBodyLimit, Path as RoutePath, Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response as AxumResponse},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mealy_application::{
    EXTENSION_POLICY_VERSION, MAXIMUM_EFFECT_OUTCOME_DETAILS_BYTES, ScheduleDefinition,
    sha256_digest, validate_schedule_definition,
};
use mealy_domain::{
    ApprovalId, AttemptId, ContextManifestId, EffectId, EventId, ExtensionFilesystemAccess,
    ExtensionGrantId, ExtensionId, ExtensionManifest, InboxEntryId, MemoryId, MemoryRevisionId,
    PrincipalId, RunId, ScheduleId, ScheduleRunId, SessionId, TaskId, ValidationId,
};
use mealy_protocol::{
    API_VERSION, AdminStatusResponse, AdminUsageReportResponse, ApprovalDecisionCommand,
    ApprovalResolutionReceipt, CancelTaskRequest, CorrectMemoryRequest, CreateScheduleRequest,
    CreateSessionRequest, CreateSessionResponse, DeliveryMode, DoctorResponse,
    EffectAttemptResponse, EffectReconciliationReceipt, EffectResponse, EnableExtensionRequest,
    ExtensionFilesystemAccessCommand, ExtensionLifecycleRequest, ExtensionResponse,
    ExtensionStatusResponse, ExtensionsResponse, InputAdmissionResponse, LocalConnectionInfo,
    MemoriesResponse, MemoryCategoryCommand, MemoryLifecycleRequest,
    MemoryPromotionAuthorizationCommand, MemoryResponse, MemoryRetentionCommand,
    MemorySearchResponse, MemorySensitivityCommand, MemorySourceCommand, MemoryStatusResponse,
    MissedRunPolicyCommand, PendingApprovalsResponse, PromoteMemoryRequest, ProposeMemoryRequest,
    ReconcileEffectRequest, ReconciliationOutcomeCommand, ResolveApprovalRequest,
    ScheduleLifecycleRequest, ScheduleOverlapPolicyCommand, ScheduleResponse,
    ScheduleRunIntentResponse, ScheduleRunResponse, ScheduleRunStatusResponse,
    ScheduleRunsResponse, ScheduleStatusResponse, SchedulesResponse, SessionStatusResponse,
    SessionsResponse, SetMemoryPinRequest, SubmitInputRequest, TaskCancellationReceipt,
    TaskResponse, TaskStatus, TimelinePageResponse,
};
use reqwest::Client;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::BTreeSet,
    io::Write as _,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq as _;
use tokio::sync::Semaphore;

const DASHBOARD_TEMPLATE: &str = include_str!("../assets/dashboard.html");
const DASHBOARD_TOKEN_HEADER: &str = "x-mealy-dashboard";
const DASHBOARD_TOKEN_PLACEHOLDER: &str = "__MEALY_DASHBOARD_TOKEN__";
const DASHBOARD_NONCE_PLACEHOLDER: &str = "__MEALY_DASHBOARD_NONCE__";
const MAXIMUM_DASHBOARD_BODY_BYTES: usize = 64 * 1024;
const MAXIMUM_DASHBOARD_INPUT_BYTES: usize = 16 * 1024;
const MAXIMUM_IDEMPOTENCY_KEY_BYTES: usize = 256;
const MAXIMUM_CANCELLATION_REASON_BYTES: usize = 1024;
const MAXIMUM_TIMELINE_PAGE_SIZE: usize = 200;
const MAXIMUM_DASHBOARD_SCHEDULES: usize = 1_000;
const MAXIMUM_SCHEDULE_RUNS_PAGE_SIZE: usize = 100;
const MAXIMUM_SCHEDULE_RUN_REASON_BYTES: usize = 4 * 1024;
const MAXIMUM_DASHBOARD_SCHEDULE_PROMPT_BYTES: usize = 48 * 1024;
const MAXIMUM_DASHBOARD_MEMORIES: usize = 1_000;
const MAXIMUM_DASHBOARD_MEMORY_REVISIONS: usize = 1_024;
const MAXIMUM_DASHBOARD_MEMORY_CONTENT_BYTES: usize = 48 * 1024;
const MAXIMUM_DASHBOARD_MEMORY_SEARCH_BYTES: usize = 4 * 1024;
const MAXIMUM_DASHBOARD_MEMORY_SEARCH_RESULTS: usize = 100;
const MAXIMUM_MEMORY_SOURCES: usize = 64;
const MAXIMUM_MEMORY_SOURCE_LOCATOR_BYTES: usize = 4 * 1024;
const DASHBOARD_MEMORY_SOURCE_PREFIX: &str = "owner://mealyctl/dashboard/";
const MAXIMUM_DASHBOARD_EXTENSIONS: usize = 1_000;
const MAXIMUM_DASHBOARD_EXTENSION_HISTORY: usize = 1_024;
const MAXIMUM_DASHBOARD_EXTENSION_GRANT_ITEMS: usize = 128;
const MAXIMUM_DASHBOARD_EXTENSION_PATH_BYTES: usize = 4 * 1024;
const MAXIMUM_DASHBOARD_EXTENSION_IDENTITY_BYTES: usize = 255;
const MAXIMUM_JAVASCRIPT_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAXIMUM_TASK_CRITERIA: usize = 64;
const MAXIMUM_TASK_CONTRACT_TEXT_BYTES: usize = 4 * 1024;
const USAGE_DAY_MS: i64 = 86_400_000;
const DASHBOARD_USAGE_DAYS: i64 = 30;

#[derive(Clone)]
struct DashboardState {
    home: Arc<PathBuf>,
    client: Client,
    authority: Arc<str>,
    origin: Arc<str>,
    token: [u8; 32],
    html: Arc<str>,
    content_security_policy: HeaderValue,
    snapshot_permit: Arc<Semaphore>,
    timeline_permit: Arc<Semaphore>,
    detail_permit: Arc<Semaphore>,
    command_permit: Arc<Semaphore>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DashboardSnapshot {
    api_version: String,
    generated_at_ms: u64,
    status: AdminStatusResponse,
    doctor: DoctorResponse,
    sessions: SessionsResponse,
    approvals: PendingApprovalsResponse,
    schedules: SchedulesResponse,
    usage: AdminUsageReportResponse,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DashboardConversation {
    api_version: String,
    status: SessionStatusResponse,
    timeline: TimelinePageResponse,
    active_task_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DashboardCreateSessionRequest {
    api_version: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DashboardSubmitInputRequest {
    api_version: String,
    idempotency_key: String,
    delivery_mode: DeliveryMode,
    content: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DashboardResolveApprovalRequest {
    api_version: String,
    idempotency_key: String,
    expected_subject_digest: String,
    decision: ApprovalDecisionCommand,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DashboardCancelTaskRequest {
    api_version: String,
    idempotency_key: String,
    reason: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DashboardReconcileEffectRequest {
    api_version: String,
    idempotency_key: String,
    expected_effect_revision: u64,
    outcome: ReconciliationOutcomeCommand,
    evidence: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DashboardScheduleLifecycleRequest {
    api_version: String,
    expected_revision: u64,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DashboardCreateScheduleRequest {
    api_version: String,
    schedule_id: String,
    session_id: String,
    name: String,
    prompt: String,
    cron_expression: String,
    timezone: String,
    missed_run_policy: MissedRunPolicyCommand,
    overlap_policy: ScheduleOverlapPolicyCommand,
    misfire_grace_ms: i64,
    allow_approval_required_action: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DashboardMemoryListRequest {
    api_version: String,
    workspace_identity: String,
    include_deleted: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DashboardMemorySearchRequest {
    api_version: String,
    workspace_identity: String,
    query: String,
    maximum_sensitivity: MemorySensitivityCommand,
    limit: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DashboardMemoryDetailRequest {
    api_version: String,
    workspace_identity: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DashboardProposeMemoryRequest {
    api_version: String,
    idempotency_key: String,
    workspace_identity: String,
    content: String,
    category: MemoryCategoryCommand,
    confidence_basis_points: u16,
    sensitivity: MemorySensitivityCommand,
    retention: MemoryRetentionCommand,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DashboardActivateMemoryRequest {
    api_version: String,
    workspace_identity: String,
    expected_revision: u64,
    revision_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DashboardCorrectMemoryRequest {
    api_version: String,
    idempotency_key: String,
    workspace_identity: String,
    expected_revision: u64,
    content: String,
    confidence_basis_points: u16,
    sensitivity: MemorySensitivityCommand,
    retention: MemoryRetentionCommand,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DashboardPinMemoryRequest {
    api_version: String,
    workspace_identity: String,
    expected_revision: u64,
    pinned: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DashboardMemoryLifecycleRequest {
    api_version: String,
    workspace_identity: String,
    expected_revision: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DashboardExtensionReadRequest {
    api_version: String,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DashboardEnableExtensionRequest {
    api_version: String,
    expected_revision: u64,
    capability_ids: Vec<String>,
    mounts: Vec<mealy_protocol::ExtensionMountGrantCommand>,
    network_destinations: Vec<String>,
    secret_references: Vec<String>,
    allow_process_spawn: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DashboardExtensionLifecycleRequest {
    api_version: String,
    expected_revision: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DashboardTaskUsageRequest {
    api_version: String,
}

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DashboardTimelineParameters {
    after: Option<u64>,
    limit: Option<usize>,
}

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DashboardScheduleRunParameters {
    limit: Option<usize>,
}

#[derive(Clone, Copy)]
enum DashboardScheduleAction {
    Pause,
    Resume,
    Cancel,
}

#[derive(Clone, Copy)]
enum DashboardMemoryLifecycleAction {
    Expire,
    Reject,
    Delete,
}

#[derive(Clone, Copy)]
enum DashboardExtensionLifecycleAction {
    Disable,
    Revoke,
}

impl DashboardExtensionLifecycleAction {
    const fn path_segment(self) -> &'static str {
        match self {
            Self::Disable => "disable",
            Self::Revoke => "revoke",
        }
    }

    const fn expected_status(self) -> ExtensionStatusResponse {
        match self {
            Self::Disable => ExtensionStatusResponse::Disabled,
            Self::Revoke => ExtensionStatusResponse::Revoked,
        }
    }

    const fn accepts_source(self, status: ExtensionStatusResponse) -> bool {
        match self {
            Self::Disable => matches!(status, ExtensionStatusResponse::Enabled),
            Self::Revoke => !matches!(status, ExtensionStatusResponse::Revoked),
        }
    }
}

impl DashboardMemoryLifecycleAction {
    const fn path_segment(self) -> &'static str {
        match self {
            Self::Expire => "expire",
            Self::Reject => "reject",
            Self::Delete => "delete",
        }
    }

    const fn expected_status(self) -> MemoryStatusResponse {
        match self {
            Self::Expire => MemoryStatusResponse::Expired,
            Self::Reject => MemoryStatusResponse::Rejected,
            Self::Delete => MemoryStatusResponse::Deleted,
        }
    }
}

impl DashboardScheduleAction {
    const fn path_segment(self) -> &'static str {
        match self {
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Cancel => "cancel",
        }
    }

    const fn expected_status(self) -> ScheduleStatusResponse {
        match self {
            Self::Pause => ScheduleStatusResponse::Paused,
            Self::Resume => ScheduleStatusResponse::Active,
            Self::Cancel => ScheduleStatusResponse::Cancelled,
        }
    }
}

/// Serves the foreground dashboard until Ctrl-C.
#[allow(clippy::too_many_lines)]
pub(crate) async fn run(
    home: &Path,
    initial_connection: &LocalConnectionInfo,
) -> Result<(), CliError> {
    let client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .build()?;
    // Refuse to advertise a dashboard that cannot obtain its exact bounded projection.
    fetch_snapshot(&client, initial_connection).await?;

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let address = listener.local_addr()?;
    let authority = format!("127.0.0.1:{}", address.port());
    let origin = format!("http://{authority}");
    let mut token = [0_u8; 32];
    let mut nonce = [0_u8; 18];
    getrandom::fill(&mut token).map_err(|_| CliError::RandomUnavailable)?;
    getrandom::fill(&mut nonce).map_err(|_| CliError::RandomUnavailable)?;
    let encoded_token = URL_SAFE_NO_PAD.encode(token);
    let encoded_nonce = URL_SAFE_NO_PAD.encode(nonce);
    let html = DASHBOARD_TEMPLATE
        .replace(DASHBOARD_TOKEN_PLACEHOLDER, &encoded_token)
        .replace(DASHBOARD_NONCE_PLACEHOLDER, &encoded_nonce);
    if html.contains(DASHBOARD_TOKEN_PLACEHOLDER)
        || html.contains(DASHBOARD_NONCE_PLACEHOLDER)
        || html.contains(&initial_connection.bearer_token)
    {
        return Err(CliError::Protocol(
            "dashboard template substitution failed closed".to_owned(),
        ));
    }
    let content_security_policy = HeaderValue::from_str(&format!(
        "default-src 'none'; base-uri 'none'; connect-src 'self'; form-action 'none'; \
         frame-ancestors 'none'; img-src 'self' data:; script-src 'nonce-{encoded_nonce}'; \
         style-src 'nonce-{encoded_nonce}'"
    ))
    .map_err(|_| CliError::Protocol("dashboard CSP could not be encoded".to_owned()))?;
    let state = DashboardState {
        home: Arc::new(home.to_owned()),
        client,
        authority: Arc::from(authority),
        origin: Arc::from(origin.clone()),
        token,
        html: Arc::from(html),
        content_security_policy,
        snapshot_permit: Arc::new(Semaphore::new(1)),
        timeline_permit: Arc::new(Semaphore::new(1)),
        detail_permit: Arc::new(Semaphore::new(1)),
        command_permit: Arc::new(Semaphore::new(1)),
    };
    let application = Router::new()
        .route("/", get(index))
        .route("/api/snapshot", get(snapshot))
        .route("/api/sessions", post(create_session))
        .route(
            "/api/sessions/{session_id}/timeline",
            get(conversation_timeline),
        )
        .route(
            "/api/sessions/{session_id}/inputs",
            post(submit_session_input),
        )
        .route(
            "/api/approvals/{approval_id}/resolve",
            post(resolve_approval),
        )
        .route("/api/tasks/{task_id}/cancel", post(cancel_task))
        .route("/api/tasks/{task_id}/usage", post(task_usage))
        .route("/api/effects/{effect_id}", get(effect_detail))
        .route(
            "/api/effect-attempts/{attempt_id}",
            get(effect_attempt_detail),
        )
        .route(
            "/api/effects/{effect_id}/attempts/{attempt_id}/reconcile",
            post(reconcile_effect),
        )
        .route("/api/schedules/{schedule_id}", get(schedule_detail))
        .route("/api/schedules", post(create_schedule))
        .route("/api/schedules/{schedule_id}/runs", get(schedule_runs))
        .route("/api/schedules/{schedule_id}/pause", post(pause_schedule))
        .route("/api/schedules/{schedule_id}/resume", post(resume_schedule))
        .route("/api/schedules/{schedule_id}/cancel", post(cancel_schedule))
        .route("/api/memories/list", post(memory_list))
        .route("/api/memories/search", post(memory_search))
        .route("/api/memories", post(propose_memory))
        .route("/api/memories/{memory_id}/detail", post(memory_detail))
        .route("/api/memories/{memory_id}/activate", post(activate_memory))
        .route("/api/memories/{memory_id}/correct", post(correct_memory))
        .route("/api/memories/{memory_id}/pin", post(pin_memory))
        .route("/api/memories/{memory_id}/expire", post(expire_memory))
        .route("/api/memories/{memory_id}/reject", post(reject_memory))
        .route("/api/memories/{memory_id}/delete", post(delete_memory))
        .route("/api/extensions/list", post(extension_list))
        .route(
            "/api/extensions/{extension_id}/detail",
            post(extension_detail),
        )
        .route(
            "/api/extensions/{extension_id}/enable",
            post(enable_extension),
        )
        .route(
            "/api/extensions/{extension_id}/disable",
            post(disable_extension),
        )
        .route(
            "/api/extensions/{extension_id}/revoke",
            post(revoke_extension),
        )
        .method_not_allowed_fallback(method_not_allowed)
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(MAXIMUM_DASHBOARD_BODY_BYTES))
        .with_state(state);

    println!("Mealy interactive dashboard: {origin}/");
    println!("Press Ctrl-C to stop the temporary loopback server.");
    std::io::stdout().flush()?;
    axum::serve(listener, application)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

async fn index(State(state): State<DashboardState>, headers: HeaderMap) -> AxumResponse {
    if !valid_dashboard_request_origin(&state, &headers) {
        return secure_response(
            dashboard_error(
                StatusCode::MISDIRECTED_REQUEST,
                "dashboard_origin_denied",
                "The dashboard accepts only its exact numeric loopback origin.",
            ),
            &state,
        );
    }
    secure_response(Html(state.html.to_string()).into_response(), &state)
}

async fn snapshot(State(state): State<DashboardState>, headers: HeaderMap) -> AxumResponse {
    if let Some(response) = authorize_dashboard_read(&state, &headers) {
        return response;
    }
    let Ok(_permit) = Arc::clone(&state.snapshot_permit).try_acquire_owned() else {
        return secure_response(
            dashboard_error(
                StatusCode::TOO_MANY_REQUESTS,
                "dashboard_refresh_in_progress",
                "A dashboard refresh is already in progress.",
            ),
            &state,
        );
    };
    let response = if let Ok(connection) = dashboard_connection(&state) {
        match fetch_snapshot(&state.client, &connection).await {
            Ok(snapshot) => Json(snapshot).into_response(),
            Err(error) => {
                eprintln!("dashboard snapshot refresh failed: {error}");
                let _ = std::io::stderr().flush();
                dashboard_backend_error(&error, "snapshot")
            }
        }
    } else {
        eprintln!("dashboard snapshot refresh could not load the connection descriptor");
        let _ = std::io::stderr().flush();
        dashboard_connection_error()
    };
    secure_response(response, &state)
}

async fn create_session(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    request: Result<Json<DashboardCreateSessionRequest>, JsonRejection>,
) -> AxumResponse {
    if let Some(response) = authorize_dashboard_mutation(&state, &headers) {
        return response;
    }
    let Ok(Json(request)) = request else {
        return secure_response(invalid_dashboard_json(), &state);
    };
    if !valid_api_version(&request.api_version) {
        return secure_response(invalid_dashboard_command(), &state);
    }
    let Ok(_permit) = Arc::clone(&state.command_permit).try_acquire_owned() else {
        return secure_response(command_in_progress(), &state);
    };
    let response = match dashboard_connection(&state) {
        Ok(connection) => {
            let command = CreateSessionRequest {
                api_version: API_VERSION.to_owned(),
            };
            match post_to_daemon::<_, CreateSessionResponse>(
                &state.client,
                &connection,
                "/v1/sessions",
                &command,
            )
            .await
            {
                Ok(response)
                    if valid_api_version(&response.api_version)
                        && response.session_id.parse::<SessionId>().is_ok() =>
                {
                    Json(response).into_response()
                }
                Ok(_) => dashboard_protocol_error("session creation"),
                Err(error) => dashboard_backend_error(&error, "session creation"),
            }
        }
        Err(()) => dashboard_connection_error(),
    };
    secure_response(response, &state)
}

async fn conversation_timeline(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    RoutePath(session_id): RoutePath<String>,
    parameters: Result<Query<DashboardTimelineParameters>, QueryRejection>,
) -> AxumResponse {
    if let Some(response) = authorize_dashboard_read(&state, &headers) {
        return response;
    }
    let Ok(session_id) = session_id.parse::<SessionId>() else {
        return secure_response(invalid_dashboard_identifier(), &state);
    };
    let Ok(Query(parameters)) = parameters else {
        return secure_response(invalid_dashboard_query(), &state);
    };
    let limit = parameters.limit.unwrap_or(MAXIMUM_TIMELINE_PAGE_SIZE);
    if !(1..=MAXIMUM_TIMELINE_PAGE_SIZE).contains(&limit) {
        return secure_response(invalid_dashboard_query(), &state);
    }
    let Ok(_permit) = Arc::clone(&state.timeline_permit).try_acquire_owned() else {
        return secure_response(
            dashboard_error(
                StatusCode::TOO_MANY_REQUESTS,
                "dashboard_timeline_in_progress",
                "A conversation refresh is already in progress.",
            ),
            &state,
        );
    };
    let response = match dashboard_connection(&state) {
        Ok(connection) => {
            let session_id = session_id.to_string();
            let status_path = format!("/v1/sessions/{session_id}/status");
            let after = parameters.after.unwrap_or(0);
            let timeline_path =
                format!("/v1/sessions/{session_id}/timeline?after={after}&limit={limit}");
            let status = fetch::<SessionStatusResponse>(&state.client, &connection, &status_path);
            let timeline =
                fetch::<TimelinePageResponse>(&state.client, &connection, &timeline_path);
            match tokio::join!(status, timeline) {
                (Ok(status), Ok(timeline))
                    if valid_api_version(&status.api_version)
                        && valid_api_version(&timeline.api_version)
                        && status.session_id == session_id =>
                {
                    let active_task_id = active_task_id(&status, &timeline);
                    Json(DashboardConversation {
                        api_version: API_VERSION.to_owned(),
                        status,
                        timeline,
                        active_task_id,
                    })
                    .into_response()
                }
                (Err(error), _) | (_, Err(error)) => {
                    dashboard_backend_error(&error, "conversation refresh")
                }
                _ => dashboard_protocol_error("conversation refresh"),
            }
        }
        Err(()) => dashboard_connection_error(),
    };
    secure_response(response, &state)
}

async fn submit_session_input(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    RoutePath(session_id): RoutePath<String>,
    request: Result<Json<DashboardSubmitInputRequest>, JsonRejection>,
) -> AxumResponse {
    if let Some(response) = authorize_dashboard_mutation(&state, &headers) {
        return response;
    }
    let Ok(session_id) = session_id.parse::<SessionId>() else {
        return secure_response(invalid_dashboard_identifier(), &state);
    };
    let Ok(Json(request)) = request else {
        return secure_response(invalid_dashboard_json(), &state);
    };
    if !valid_api_version(&request.api_version)
        || !valid_idempotency_key(&request.idempotency_key)
        || request.content.trim().is_empty()
        || request.content.len() > MAXIMUM_DASHBOARD_INPUT_BYTES
    {
        return secure_response(invalid_dashboard_command(), &state);
    }
    let Ok(_permit) = Arc::clone(&state.command_permit).try_acquire_owned() else {
        return secure_response(command_in_progress(), &state);
    };
    let response = match dashboard_connection(&state) {
        Ok(connection) => {
            let session_id = session_id.to_string();
            let command = SubmitInputRequest {
                api_version: API_VERSION.to_owned(),
                idempotency_key: request.idempotency_key,
                delivery_mode: request.delivery_mode,
                content: request.content,
            };
            let path = format!("/v1/sessions/{session_id}/inputs");
            match post_to_daemon::<_, InputAdmissionResponse>(
                &state.client,
                &connection,
                &path,
                &command,
            )
            .await
            {
                Ok(response)
                    if valid_api_version(&response.api_version)
                        && response.session_id == session_id =>
                {
                    Json(response).into_response()
                }
                Ok(_) => dashboard_protocol_error("input admission"),
                Err(error) => dashboard_backend_error(&error, "input admission"),
            }
        }
        Err(()) => dashboard_connection_error(),
    };
    secure_response(response, &state)
}

async fn resolve_approval(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    RoutePath(approval_id): RoutePath<String>,
    request: Result<Json<DashboardResolveApprovalRequest>, JsonRejection>,
) -> AxumResponse {
    if let Some(response) = authorize_dashboard_mutation(&state, &headers) {
        return response;
    }
    let Ok(approval_id) = approval_id.parse::<ApprovalId>() else {
        return secure_response(invalid_dashboard_identifier(), &state);
    };
    let Ok(Json(request)) = request else {
        return secure_response(invalid_dashboard_json(), &state);
    };
    if !valid_api_version(&request.api_version)
        || !valid_idempotency_key(&request.idempotency_key)
        || !valid_sha256_digest(&request.expected_subject_digest)
    {
        return secure_response(invalid_dashboard_command(), &state);
    }
    let Ok(_permit) = Arc::clone(&state.command_permit).try_acquire_owned() else {
        return secure_response(command_in_progress(), &state);
    };
    let response = match dashboard_connection(&state) {
        Ok(connection) => {
            let approval_id = approval_id.to_string();
            let command = ResolveApprovalRequest {
                api_version: API_VERSION.to_owned(),
                idempotency_key: request.idempotency_key,
                expected_subject_digest: request.expected_subject_digest,
                decision: request.decision,
            };
            let path = format!("/v1/approvals/{approval_id}/resolve");
            match post_to_daemon::<_, ApprovalResolutionReceipt>(
                &state.client,
                &connection,
                &path,
                &command,
            )
            .await
            {
                Ok(response)
                    if valid_api_version(&response.api_version)
                        && response.approval_id == approval_id =>
                {
                    Json(response).into_response()
                }
                Ok(_) => dashboard_protocol_error("approval resolution"),
                Err(error) => dashboard_backend_error(&error, "approval resolution"),
            }
        }
        Err(()) => dashboard_connection_error(),
    };
    secure_response(response, &state)
}

async fn cancel_task(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    RoutePath(task_id): RoutePath<String>,
    request: Result<Json<DashboardCancelTaskRequest>, JsonRejection>,
) -> AxumResponse {
    if let Some(response) = authorize_dashboard_mutation(&state, &headers) {
        return response;
    }
    let Ok(task_id) = task_id.parse::<TaskId>() else {
        return secure_response(invalid_dashboard_identifier(), &state);
    };
    let Ok(Json(request)) = request else {
        return secure_response(invalid_dashboard_json(), &state);
    };
    if !valid_api_version(&request.api_version)
        || !valid_idempotency_key(&request.idempotency_key)
        || request.reason.trim().is_empty()
        || request.reason.trim() != request.reason
        || request.reason.len() > MAXIMUM_CANCELLATION_REASON_BYTES
        || request.reason.chars().any(char::is_control)
    {
        return secure_response(invalid_dashboard_command(), &state);
    }
    let Ok(_permit) = Arc::clone(&state.command_permit).try_acquire_owned() else {
        return secure_response(command_in_progress(), &state);
    };
    let response = match dashboard_connection(&state) {
        Ok(connection) => {
            let task_id = task_id.to_string();
            let command = CancelTaskRequest {
                api_version: API_VERSION.to_owned(),
                idempotency_key: request.idempotency_key,
                reason: request.reason,
            };
            let path = format!("/v1/tasks/{task_id}/cancel");
            match post_to_daemon::<_, TaskCancellationReceipt>(
                &state.client,
                &connection,
                &path,
                &command,
            )
            .await
            {
                Ok(response)
                    if valid_api_version(&response.api_version) && response.task_id == task_id =>
                {
                    Json(response).into_response()
                }
                Ok(_) => dashboard_protocol_error("task cancellation"),
                Err(error) => dashboard_backend_error(&error, "task cancellation"),
            }
        }
        Err(()) => dashboard_connection_error(),
    };
    secure_response(response, &state)
}

async fn task_usage(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    RoutePath(task_id): RoutePath<String>,
    request: Result<Json<DashboardTaskUsageRequest>, JsonRejection>,
) -> AxumResponse {
    if let Some(response) = authorize_dashboard_mutation(&state, &headers) {
        return response;
    }
    let Ok(task_id) = task_id.parse::<TaskId>() else {
        return secure_response(invalid_dashboard_identifier(), &state);
    };
    let Ok(Json(request)) = request else {
        return secure_response(invalid_dashboard_json(), &state);
    };
    if !valid_api_version(&request.api_version) {
        return secure_response(invalid_dashboard_command(), &state);
    }
    let Ok(_permit) = Arc::clone(&state.detail_permit).try_acquire_owned() else {
        return secure_response(detail_in_progress(), &state);
    };
    let response = match dashboard_connection(&state) {
        Ok(connection) => {
            let task_id = task_id.to_string();
            let path = format!("/v1/tasks/{task_id}");
            match fetch::<TaskResponse>(&state.client, &connection, &path).await {
                Ok(response) if valid_task_response(&response, &task_id) => {
                    Json(response).into_response()
                }
                Ok(_) => dashboard_protocol_error("task usage"),
                Err(error) => dashboard_backend_error(&error, "task usage"),
            }
        }
        Err(()) => dashboard_connection_error(),
    };
    secure_response(response, &state)
}

async fn effect_detail(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    RoutePath(effect_id): RoutePath<String>,
) -> AxumResponse {
    if let Some(response) = authorize_dashboard_read(&state, &headers) {
        return response;
    }
    let Ok(effect_id) = effect_id.parse::<EffectId>() else {
        return secure_response(invalid_dashboard_identifier(), &state);
    };
    let Ok(_permit) = Arc::clone(&state.detail_permit).try_acquire_owned() else {
        return secure_response(detail_in_progress(), &state);
    };
    let response = match dashboard_connection(&state) {
        Ok(connection) => {
            let effect_id = effect_id.to_string();
            let path = format!("/v1/effects/{effect_id}");
            match fetch::<EffectResponse>(&state.client, &connection, &path).await {
                Ok(response)
                    if valid_api_version(&response.api_version)
                        && response.effect_id == effect_id
                        && response.task_id.parse::<TaskId>().is_ok()
                        && response.run_id.parse::<RunId>().is_ok()
                        && response.normalized_arguments.is_object()
                        && valid_sha256_digest(&response.descriptor_digest)
                        && valid_sha256_digest(&response.arguments_digest)
                        && valid_sha256_digest(&response.executable_identity_digest) =>
                {
                    Json(response).into_response()
                }
                Ok(_) => dashboard_protocol_error("effect detail"),
                Err(error) => dashboard_backend_error(&error, "effect detail"),
            }
        }
        Err(()) => dashboard_connection_error(),
    };
    secure_response(response, &state)
}

async fn effect_attempt_detail(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    RoutePath(attempt_id): RoutePath<String>,
) -> AxumResponse {
    if let Some(response) = authorize_dashboard_read(&state, &headers) {
        return response;
    }
    let Ok(attempt_id) = attempt_id.parse::<AttemptId>() else {
        return secure_response(invalid_dashboard_identifier(), &state);
    };
    let Ok(_permit) = Arc::clone(&state.detail_permit).try_acquire_owned() else {
        return secure_response(detail_in_progress(), &state);
    };
    let response = match dashboard_connection(&state) {
        Ok(connection) => {
            let attempt_id = attempt_id.to_string();
            let path = format!("/v1/effect-attempts/{attempt_id}");
            match fetch::<EffectAttemptResponse>(&state.client, &connection, &path).await {
                Ok(response)
                    if valid_api_version(&response.api_version)
                        && response.attempt_id == attempt_id
                        && response.effect_id.parse::<EffectId>().is_ok()
                        && response.ordinal > 0
                        && response.fencing_token > 0 =>
                {
                    Json(response).into_response()
                }
                Ok(_) => dashboard_protocol_error("effect-attempt detail"),
                Err(error) => dashboard_backend_error(&error, "effect-attempt detail"),
            }
        }
        Err(()) => dashboard_connection_error(),
    };
    secure_response(response, &state)
}

async fn reconcile_effect(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    RoutePath((effect_id, attempt_id)): RoutePath<(String, String)>,
    request: Result<Json<DashboardReconcileEffectRequest>, JsonRejection>,
) -> AxumResponse {
    if let Some(response) = authorize_dashboard_mutation(&state, &headers) {
        return response;
    }
    let (Ok(effect_id), Ok(attempt_id)) = (
        effect_id.parse::<EffectId>(),
        attempt_id.parse::<AttemptId>(),
    ) else {
        return secure_response(invalid_dashboard_identifier(), &state);
    };
    let Ok(Json(request)) = request else {
        return secure_response(invalid_dashboard_json(), &state);
    };
    if !valid_api_version(&request.api_version)
        || !valid_idempotency_key(&request.idempotency_key)
        || !valid_reconciliation_evidence(&request.evidence)
    {
        return secure_response(invalid_dashboard_command(), &state);
    }
    let Ok(_permit) = Arc::clone(&state.command_permit).try_acquire_owned() else {
        return secure_response(command_in_progress(), &state);
    };
    let response = match dashboard_connection(&state) {
        Ok(connection) => {
            let effect_id = effect_id.to_string();
            let attempt_id = attempt_id.to_string();
            let path = format!("/v1/effects/{effect_id}/attempts/{attempt_id}/reconcile");
            let command = ReconcileEffectRequest {
                api_version: API_VERSION.to_owned(),
                idempotency_key: request.idempotency_key,
                expected_effect_revision: request.expected_effect_revision,
                outcome: request.outcome,
                evidence: request.evidence,
            };
            match post_to_daemon::<_, EffectReconciliationReceipt>(
                &state.client,
                &connection,
                &path,
                &command,
            )
            .await
            {
                Ok(response)
                    if valid_api_version(&response.api_version)
                        && response.effect_id == effect_id
                        && response.attempt_id == attempt_id
                        && response.outcome == command.outcome
                        && request.expected_effect_revision.checked_add(1)
                            == Some(response.effect_revision)
                        && response.event_id.parse::<EventId>().is_ok()
                        && response.cursor.0 > 0 =>
                {
                    Json(response).into_response()
                }
                Ok(_) => dashboard_protocol_error("effect reconciliation"),
                Err(error) => dashboard_backend_error(&error, "effect reconciliation"),
            }
        }
        Err(()) => dashboard_connection_error(),
    };
    secure_response(response, &state)
}

async fn create_schedule(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    request: Result<Json<DashboardCreateScheduleRequest>, JsonRejection>,
) -> AxumResponse {
    if let Some(response) = authorize_dashboard_mutation(&state, &headers) {
        return response;
    }
    let Ok(Json(request)) = request else {
        return secure_response(invalid_dashboard_json(), &state);
    };
    if !valid_dashboard_schedule_create_request(&request) {
        return secure_response(invalid_dashboard_command(), &state);
    }
    let Ok(_permit) = Arc::clone(&state.command_permit).try_acquire_owned() else {
        return secure_response(command_in_progress(), &state);
    };
    let response = match dashboard_connection(&state) {
        Ok(connection) => {
            let command = CreateScheduleRequest {
                api_version: API_VERSION.to_owned(),
                schedule_id: request.schedule_id.clone(),
                session_id: request.session_id.clone(),
                name: request.name.clone(),
                prompt: request.prompt.clone(),
                cron_expression: request.cron_expression.clone(),
                timezone: request.timezone.clone(),
                missed_run_policy: request.missed_run_policy,
                overlap_policy: request.overlap_policy,
                misfire_grace_ms: request.misfire_grace_ms,
                allow_approval_required_action: request.allow_approval_required_action,
            };
            match post_to_daemon::<_, ScheduleResponse>(
                &state.client,
                &connection,
                "/v1/schedules",
                &command,
            )
            .await
            {
                Ok(response)
                    if valid_schedule_response(&response, &request.schedule_id)
                        && schedule_matches_create_request(&response, &request) =>
                {
                    Json(response).into_response()
                }
                Ok(_) => dashboard_protocol_error("schedule creation"),
                Err(error) => dashboard_backend_error(&error, "schedule creation"),
            }
        }
        Err(()) => dashboard_connection_error(),
    };
    secure_response(response, &state)
}

async fn schedule_detail(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    RoutePath(schedule_id): RoutePath<String>,
) -> AxumResponse {
    if let Some(response) = authorize_dashboard_read(&state, &headers) {
        return response;
    }
    let Ok(schedule_id) = schedule_id.parse::<ScheduleId>() else {
        return secure_response(invalid_dashboard_identifier(), &state);
    };
    let Ok(_permit) = Arc::clone(&state.detail_permit).try_acquire_owned() else {
        return secure_response(detail_in_progress(), &state);
    };
    let response = match dashboard_connection(&state) {
        Ok(connection) => {
            let schedule_id = schedule_id.to_string();
            let path = format!("/v1/schedules/{schedule_id}");
            match fetch::<ScheduleResponse>(&state.client, &connection, &path).await {
                Ok(response) if valid_schedule_response(&response, &schedule_id) => {
                    Json(response).into_response()
                }
                Ok(_) => dashboard_protocol_error("schedule detail"),
                Err(error) => dashboard_backend_error(&error, "schedule detail"),
            }
        }
        Err(()) => dashboard_connection_error(),
    };
    secure_response(response, &state)
}

async fn schedule_runs(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    RoutePath(schedule_id): RoutePath<String>,
    parameters: Result<Query<DashboardScheduleRunParameters>, QueryRejection>,
) -> AxumResponse {
    if let Some(response) = authorize_dashboard_read(&state, &headers) {
        return response;
    }
    let Ok(schedule_id) = schedule_id.parse::<ScheduleId>() else {
        return secure_response(invalid_dashboard_identifier(), &state);
    };
    let Ok(Query(parameters)) = parameters else {
        return secure_response(invalid_dashboard_query(), &state);
    };
    let limit = parameters.limit.unwrap_or(MAXIMUM_SCHEDULE_RUNS_PAGE_SIZE);
    if !(1..=MAXIMUM_SCHEDULE_RUNS_PAGE_SIZE).contains(&limit) {
        return secure_response(invalid_dashboard_query(), &state);
    }
    let Ok(_permit) = Arc::clone(&state.detail_permit).try_acquire_owned() else {
        return secure_response(detail_in_progress(), &state);
    };
    let response = match dashboard_connection(&state) {
        Ok(connection) => {
            let schedule_id = schedule_id.to_string();
            let path = format!("/v1/schedules/{schedule_id}/runs?limit={limit}");
            match fetch::<ScheduleRunsResponse>(&state.client, &connection, &path).await {
                Ok(response) if valid_schedule_runs_response(&response, &schedule_id, limit) => {
                    Json(response).into_response()
                }
                Ok(_) => dashboard_protocol_error("schedule run history"),
                Err(error) => dashboard_backend_error(&error, "schedule run history"),
            }
        }
        Err(()) => dashboard_connection_error(),
    };
    secure_response(response, &state)
}

async fn pause_schedule(
    state: State<DashboardState>,
    headers: HeaderMap,
    schedule_id: RoutePath<String>,
    request: Result<Json<DashboardScheduleLifecycleRequest>, JsonRejection>,
) -> AxumResponse {
    schedule_lifecycle(
        state,
        headers,
        schedule_id,
        request,
        DashboardScheduleAction::Pause,
    )
    .await
}

async fn resume_schedule(
    state: State<DashboardState>,
    headers: HeaderMap,
    schedule_id: RoutePath<String>,
    request: Result<Json<DashboardScheduleLifecycleRequest>, JsonRejection>,
) -> AxumResponse {
    schedule_lifecycle(
        state,
        headers,
        schedule_id,
        request,
        DashboardScheduleAction::Resume,
    )
    .await
}

async fn cancel_schedule(
    state: State<DashboardState>,
    headers: HeaderMap,
    schedule_id: RoutePath<String>,
    request: Result<Json<DashboardScheduleLifecycleRequest>, JsonRejection>,
) -> AxumResponse {
    schedule_lifecycle(
        state,
        headers,
        schedule_id,
        request,
        DashboardScheduleAction::Cancel,
    )
    .await
}

async fn schedule_lifecycle(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    RoutePath(schedule_id): RoutePath<String>,
    request: Result<Json<DashboardScheduleLifecycleRequest>, JsonRejection>,
    action: DashboardScheduleAction,
) -> AxumResponse {
    if let Some(response) = authorize_dashboard_mutation(&state, &headers) {
        return response;
    }
    let Ok(schedule_id) = schedule_id.parse::<ScheduleId>() else {
        return secure_response(invalid_dashboard_identifier(), &state);
    };
    let Ok(Json(request)) = request else {
        return secure_response(invalid_dashboard_json(), &state);
    };
    let Some(expected_response_revision) = request.expected_revision.checked_add(1) else {
        return secure_response(invalid_dashboard_command(), &state);
    };
    if !valid_api_version(&request.api_version) {
        return secure_response(invalid_dashboard_command(), &state);
    }
    let Ok(_permit) = Arc::clone(&state.command_permit).try_acquire_owned() else {
        return secure_response(command_in_progress(), &state);
    };
    let response = match dashboard_connection(&state) {
        Ok(connection) => {
            let schedule_id = schedule_id.to_string();
            let operation = action.path_segment();
            let path = format!("/v1/schedules/{schedule_id}/{operation}");
            let command = ScheduleLifecycleRequest {
                api_version: API_VERSION.to_owned(),
                expected_revision: request.expected_revision,
            };
            match post_to_daemon::<_, ScheduleResponse>(&state.client, &connection, &path, &command)
                .await
            {
                Ok(response)
                    if valid_schedule_response(&response, &schedule_id)
                        && response.status == action.expected_status()
                        && response.revision == expected_response_revision =>
                {
                    Json(response).into_response()
                }
                Ok(_) => dashboard_protocol_error("schedule lifecycle"),
                Err(error) => dashboard_backend_error(&error, "schedule lifecycle"),
            }
        }
        Err(()) => dashboard_connection_error(),
    };
    secure_response(response, &state)
}

async fn memory_list(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    request: Result<Json<DashboardMemoryListRequest>, JsonRejection>,
) -> AxumResponse {
    if let Some(response) = authorize_dashboard_mutation(&state, &headers) {
        return response;
    }
    let Ok(Json(request)) = request else {
        return secure_response(invalid_dashboard_json(), &state);
    };
    if !valid_api_version(&request.api_version)
        || !valid_memory_workspace_identity(&request.workspace_identity)
    {
        return secure_response(invalid_dashboard_command(), &state);
    }
    let Ok(_permit) = Arc::clone(&state.detail_permit).try_acquire_owned() else {
        return secure_response(detail_in_progress(), &state);
    };
    let response = match dashboard_connection(&state) {
        Ok(connection) => match fetch_memories_from_daemon(
            &state.client,
            &connection,
            &request.workspace_identity,
            request.include_deleted,
        )
        .await
        {
            Ok(response)
                if valid_memories_response(
                    &response,
                    &request.workspace_identity,
                    request.include_deleted,
                ) =>
            {
                Json(response).into_response()
            }
            Ok(_) => dashboard_protocol_error("memory list"),
            Err(error) => dashboard_backend_error(&error, "memory list"),
        },
        Err(()) => dashboard_connection_error(),
    };
    secure_response(response, &state)
}

async fn memory_search(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    request: Result<Json<DashboardMemorySearchRequest>, JsonRejection>,
) -> AxumResponse {
    if let Some(response) = authorize_dashboard_mutation(&state, &headers) {
        return response;
    }
    let Ok(Json(request)) = request else {
        return secure_response(invalid_dashboard_json(), &state);
    };
    if !valid_api_version(&request.api_version)
        || !valid_memory_workspace_identity(&request.workspace_identity)
        || request.query.is_empty()
        || request.query.len() > MAXIMUM_DASHBOARD_MEMORY_SEARCH_BYTES
        || request.query.trim() != request.query
        || request.query.chars().any(char::is_control)
        || !(1..=MAXIMUM_DASHBOARD_MEMORY_SEARCH_RESULTS).contains(&request.limit)
    {
        return secure_response(invalid_dashboard_command(), &state);
    }
    let Ok(_permit) = Arc::clone(&state.detail_permit).try_acquire_owned() else {
        return secure_response(detail_in_progress(), &state);
    };
    let response = match dashboard_connection(&state) {
        Ok(connection) => {
            match fetch_memory_search_from_daemon(&state.client, &connection, &request).await {
                Ok(response)
                    if valid_memory_search_response(
                        &response,
                        &request.workspace_identity,
                        request.maximum_sensitivity,
                        request.limit,
                    ) =>
                {
                    Json(response).into_response()
                }
                Ok(_) => dashboard_protocol_error("memory search"),
                Err(error) => dashboard_backend_error(&error, "memory search"),
            }
        }
        Err(()) => dashboard_connection_error(),
    };
    secure_response(response, &state)
}

async fn memory_detail(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    RoutePath(memory_id): RoutePath<String>,
    request: Result<Json<DashboardMemoryDetailRequest>, JsonRejection>,
) -> AxumResponse {
    if let Some(response) = authorize_dashboard_mutation(&state, &headers) {
        return response;
    }
    let Ok(memory_id) = memory_id.parse::<MemoryId>() else {
        return secure_response(invalid_dashboard_identifier(), &state);
    };
    let Ok(Json(request)) = request else {
        return secure_response(invalid_dashboard_json(), &state);
    };
    if !valid_api_version(&request.api_version)
        || !valid_memory_workspace_identity(&request.workspace_identity)
    {
        return secure_response(invalid_dashboard_command(), &state);
    }
    let Ok(_permit) = Arc::clone(&state.detail_permit).try_acquire_owned() else {
        return secure_response(detail_in_progress(), &state);
    };
    let response = match dashboard_connection(&state) {
        Ok(connection) => {
            let memory_id = memory_id.to_string();
            match fetch_memory_from_daemon(
                &state.client,
                &connection,
                &request.workspace_identity,
                &memory_id,
            )
            .await
            {
                Ok(response)
                    if valid_memory_response(
                        &response,
                        Some(&memory_id),
                        &request.workspace_identity,
                    ) =>
                {
                    Json(response).into_response()
                }
                Ok(_) => dashboard_protocol_error("memory detail"),
                Err(error) => dashboard_backend_error(&error, "memory detail"),
            }
        }
        Err(()) => dashboard_connection_error(),
    };
    secure_response(response, &state)
}

async fn propose_memory(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    request: Result<Json<DashboardProposeMemoryRequest>, JsonRejection>,
) -> AxumResponse {
    if let Some(response) = authorize_dashboard_mutation(&state, &headers) {
        return response;
    }
    let Ok(Json(request)) = request else {
        return secure_response(invalid_dashboard_json(), &state);
    };
    if !valid_api_version(&request.api_version)
        || !valid_idempotency_key(&request.idempotency_key)
        || !valid_memory_workspace_identity(&request.workspace_identity)
        || !valid_dashboard_memory_content(&request.content)
        || request.confidence_basis_points > 10_000
    {
        return secure_response(invalid_dashboard_command(), &state);
    }
    let Ok(_permit) = Arc::clone(&state.command_permit).try_acquire_owned() else {
        return secure_response(command_in_progress(), &state);
    };
    let response = match dashboard_connection(&state) {
        Ok(connection) => {
            let source_locator = dashboard_memory_source_locator(&request.idempotency_key);
            let source_digest = sha256_digest(request.content.as_bytes());
            match fetch_memories_from_daemon(
                &state.client,
                &connection,
                &request.workspace_identity,
                true,
            )
            .await
            {
                Ok(existing)
                    if valid_memories_response(&existing, &request.workspace_identity, true) =>
                {
                    let matching = memories_with_source_locator(&existing, &source_locator);
                    if matching.len() > 1 {
                        dashboard_protocol_error("memory proposal reconciliation")
                    } else if let Some(memory) = matching.first() {
                        if memory_matches_proposal(
                            memory,
                            &request,
                            &source_locator,
                            &source_digest,
                        ) {
                            Json((*memory).clone()).into_response()
                        } else {
                            dashboard_state_conflict("memory proposal")
                        }
                    } else {
                        let command = ProposeMemoryRequest {
                            api_version: API_VERSION.to_owned(),
                            workspace_identity: request.workspace_identity.clone(),
                            content: request.content.clone(),
                            category: request.category,
                            confidence_basis_points: request.confidence_basis_points,
                            sensitivity: request.sensitivity,
                            retention: request.retention,
                            sources: vec![MemorySourceCommand {
                                locator: source_locator.clone(),
                                digest: source_digest.clone(),
                            }],
                        };
                        match post_to_daemon::<_, MemoryResponse>(
                            &state.client,
                            &connection,
                            "/v1/memories",
                            &command,
                        )
                        .await
                        {
                            Ok(response)
                                if valid_memory_response(
                                    &response,
                                    None,
                                    &request.workspace_identity,
                                ) && response.status == MemoryStatusResponse::Proposed
                                    && response.revision == 0
                                    && response.revisions.len() == 1
                                    && memory_matches_proposal(
                                        &response,
                                        &request,
                                        &source_locator,
                                        &source_digest,
                                    ) =>
                            {
                                Json(response).into_response()
                            }
                            Ok(_) => dashboard_protocol_error("memory proposal"),
                            Err(error) => dashboard_backend_error(&error, "memory proposal"),
                        }
                    }
                }
                Ok(_) => dashboard_protocol_error("memory proposal reconciliation"),
                Err(error) => dashboard_backend_error(&error, "memory proposal reconciliation"),
            }
        }
        Err(()) => dashboard_connection_error(),
    };
    secure_response(response, &state)
}

#[allow(clippy::too_many_lines)]
async fn activate_memory(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    RoutePath(memory_id): RoutePath<String>,
    request: Result<Json<DashboardActivateMemoryRequest>, JsonRejection>,
) -> AxumResponse {
    if let Some(response) = authorize_dashboard_mutation(&state, &headers) {
        return response;
    }
    let Ok(memory_id) = memory_id.parse::<MemoryId>() else {
        return secure_response(invalid_dashboard_identifier(), &state);
    };
    let Ok(Json(request)) = request else {
        return secure_response(invalid_dashboard_json(), &state);
    };
    let Ok(revision_id) = request.revision_id.parse::<MemoryRevisionId>() else {
        return secure_response(invalid_dashboard_identifier(), &state);
    };
    let Some(expected_response_revision) = request.expected_revision.checked_add(1) else {
        return secure_response(invalid_dashboard_command(), &state);
    };
    if !valid_api_version(&request.api_version)
        || !valid_memory_workspace_identity(&request.workspace_identity)
    {
        return secure_response(invalid_dashboard_command(), &state);
    }
    let Ok(_permit) = Arc::clone(&state.command_permit).try_acquire_owned() else {
        return secure_response(command_in_progress(), &state);
    };
    let response = match dashboard_connection(&state) {
        Ok(connection) => {
            let memory_id = memory_id.to_string();
            let revision_id = revision_id.to_string();
            match fetch_memory_from_daemon(
                &state.client,
                &connection,
                &request.workspace_identity,
                &memory_id,
            )
            .await
            {
                Ok(current)
                    if valid_memory_response(
                        &current,
                        Some(&memory_id),
                        &request.workspace_identity,
                    ) =>
                {
                    if current.revision == expected_response_revision
                        && current.status == MemoryStatusResponse::Active
                        && memory_revision_has_status(
                            &current,
                            &revision_id,
                            MemoryStatusResponse::Active,
                        )
                    {
                        Json(current).into_response()
                    } else if current.revision != request.expected_revision
                        || current.status != MemoryStatusResponse::Proposed
                        || !memory_revision_has_status(
                            &current,
                            &revision_id,
                            MemoryStatusResponse::Proposed,
                        )
                    {
                        dashboard_state_conflict("memory activation")
                    } else {
                        let command = PromoteMemoryRequest {
                            api_version: API_VERSION.to_owned(),
                            revision_id: revision_id.clone(),
                            authorization: Some(MemoryPromotionAuthorizationCommand::OwnerApproval),
                        };
                        let path = format!("/v1/memories/{memory_id}/activate");
                        match post_to_daemon::<_, MemoryResponse>(
                            &state.client,
                            &connection,
                            &path,
                            &command,
                        )
                        .await
                        {
                            Ok(response)
                                if valid_memory_response(
                                    &response,
                                    Some(&memory_id),
                                    &request.workspace_identity,
                                ) && response.status == MemoryStatusResponse::Active
                                    && response.revision == expected_response_revision
                                    && memory_revision_has_status(
                                        &response,
                                        &revision_id,
                                        MemoryStatusResponse::Active,
                                    ) =>
                            {
                                Json(response).into_response()
                            }
                            Ok(_) => dashboard_protocol_error("memory activation"),
                            Err(error) => dashboard_backend_error(&error, "memory activation"),
                        }
                    }
                }
                Ok(_) => dashboard_protocol_error("memory activation preflight"),
                Err(error) => dashboard_backend_error(&error, "memory activation preflight"),
            }
        }
        Err(()) => dashboard_connection_error(),
    };
    secure_response(response, &state)
}

#[allow(clippy::too_many_lines)]
async fn correct_memory(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    RoutePath(memory_id): RoutePath<String>,
    request: Result<Json<DashboardCorrectMemoryRequest>, JsonRejection>,
) -> AxumResponse {
    if let Some(response) = authorize_dashboard_mutation(&state, &headers) {
        return response;
    }
    let Ok(memory_id) = memory_id.parse::<MemoryId>() else {
        return secure_response(invalid_dashboard_identifier(), &state);
    };
    let Ok(Json(request)) = request else {
        return secure_response(invalid_dashboard_json(), &state);
    };
    let Some(expected_response_revision) = request.expected_revision.checked_add(1) else {
        return secure_response(invalid_dashboard_command(), &state);
    };
    if !valid_api_version(&request.api_version)
        || !valid_idempotency_key(&request.idempotency_key)
        || !valid_memory_workspace_identity(&request.workspace_identity)
        || !valid_dashboard_memory_content(&request.content)
        || request.confidence_basis_points > 10_000
    {
        return secure_response(invalid_dashboard_command(), &state);
    }
    let Ok(_permit) = Arc::clone(&state.command_permit).try_acquire_owned() else {
        return secure_response(command_in_progress(), &state);
    };
    let response = match dashboard_connection(&state) {
        Ok(connection) => {
            let memory_id = memory_id.to_string();
            let source_locator = dashboard_memory_source_locator(&request.idempotency_key);
            let source_digest = sha256_digest(request.content.as_bytes());
            match fetch_memory_from_daemon(
                &state.client,
                &connection,
                &request.workspace_identity,
                &memory_id,
            )
            .await
            {
                Ok(current)
                    if valid_memory_response(
                        &current,
                        Some(&memory_id),
                        &request.workspace_identity,
                    ) =>
                {
                    let source_present = memory_has_source_locator(&current, &source_locator);
                    if source_present
                        && current.revision == expected_response_revision
                        && current.status == MemoryStatusResponse::Active
                        && memory_matches_correction(
                            &current,
                            &request,
                            &source_locator,
                            &source_digest,
                        )
                    {
                        Json(current).into_response()
                    } else if source_present
                        || current.revision != request.expected_revision
                        || current.status != MemoryStatusResponse::Active
                    {
                        dashboard_state_conflict("memory correction")
                    } else {
                        let command = CorrectMemoryRequest {
                            api_version: API_VERSION.to_owned(),
                            expected_revision: request.expected_revision,
                            content: request.content.clone(),
                            confidence_basis_points: request.confidence_basis_points,
                            sensitivity: request.sensitivity,
                            retention: request.retention,
                            sources: vec![MemorySourceCommand {
                                locator: source_locator.clone(),
                                digest: source_digest.clone(),
                            }],
                            authorization: Some(MemoryPromotionAuthorizationCommand::OwnerApproval),
                        };
                        let path = format!("/v1/memories/{memory_id}/correct");
                        match post_to_daemon::<_, MemoryResponse>(
                            &state.client,
                            &connection,
                            &path,
                            &command,
                        )
                        .await
                        {
                            Ok(response)
                                if valid_memory_response(
                                    &response,
                                    Some(&memory_id),
                                    &request.workspace_identity,
                                ) && response.status == MemoryStatusResponse::Active
                                    && response.revision == expected_response_revision
                                    && memory_matches_correction(
                                        &response,
                                        &request,
                                        &source_locator,
                                        &source_digest,
                                    ) =>
                            {
                                Json(response).into_response()
                            }
                            Ok(_) => dashboard_protocol_error("memory correction"),
                            Err(error) => dashboard_backend_error(&error, "memory correction"),
                        }
                    }
                }
                Ok(_) => dashboard_protocol_error("memory correction preflight"),
                Err(error) => dashboard_backend_error(&error, "memory correction preflight"),
            }
        }
        Err(()) => dashboard_connection_error(),
    };
    secure_response(response, &state)
}

async fn pin_memory(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    RoutePath(memory_id): RoutePath<String>,
    request: Result<Json<DashboardPinMemoryRequest>, JsonRejection>,
) -> AxumResponse {
    if let Some(response) = authorize_dashboard_mutation(&state, &headers) {
        return response;
    }
    let Ok(memory_id) = memory_id.parse::<MemoryId>() else {
        return secure_response(invalid_dashboard_identifier(), &state);
    };
    let Ok(Json(request)) = request else {
        return secure_response(invalid_dashboard_json(), &state);
    };
    let Some(expected_response_revision) = request.expected_revision.checked_add(1) else {
        return secure_response(invalid_dashboard_command(), &state);
    };
    if !valid_api_version(&request.api_version)
        || !valid_memory_workspace_identity(&request.workspace_identity)
    {
        return secure_response(invalid_dashboard_command(), &state);
    }
    let expected_retention = if request.pinned {
        MemoryRetentionCommand::Pinned
    } else {
        MemoryRetentionCommand::Standard
    };
    let Ok(_permit) = Arc::clone(&state.command_permit).try_acquire_owned() else {
        return secure_response(command_in_progress(), &state);
    };
    let response = match dashboard_connection(&state) {
        Ok(connection) => {
            let memory_id = memory_id.to_string();
            match fetch_memory_from_daemon(
                &state.client,
                &connection,
                &request.workspace_identity,
                &memory_id,
            )
            .await
            {
                Ok(current)
                    if valid_memory_response(
                        &current,
                        Some(&memory_id),
                        &request.workspace_identity,
                    ) =>
                {
                    if current.revision == expected_response_revision
                        && current.status == MemoryStatusResponse::Active
                        && current.retention == expected_retention
                    {
                        Json(current).into_response()
                    } else if current.revision != request.expected_revision
                        || current.status != MemoryStatusResponse::Active
                    {
                        dashboard_state_conflict("memory pin lifecycle")
                    } else {
                        let command = SetMemoryPinRequest {
                            api_version: API_VERSION.to_owned(),
                            expected_revision: request.expected_revision,
                            pinned: request.pinned,
                        };
                        let path = format!("/v1/memories/{memory_id}/pin");
                        match post_to_daemon::<_, MemoryResponse>(
                            &state.client,
                            &connection,
                            &path,
                            &command,
                        )
                        .await
                        {
                            Ok(response)
                                if valid_memory_response(
                                    &response,
                                    Some(&memory_id),
                                    &request.workspace_identity,
                                ) && response.revision == expected_response_revision
                                    && response.status == MemoryStatusResponse::Active
                                    && response.retention == expected_retention =>
                            {
                                Json(response).into_response()
                            }
                            Ok(_) => dashboard_protocol_error("memory pin lifecycle"),
                            Err(error) => dashboard_backend_error(&error, "memory pin lifecycle"),
                        }
                    }
                }
                Ok(_) => dashboard_protocol_error("memory pin preflight"),
                Err(error) => dashboard_backend_error(&error, "memory pin preflight"),
            }
        }
        Err(()) => dashboard_connection_error(),
    };
    secure_response(response, &state)
}

async fn expire_memory(
    state: State<DashboardState>,
    headers: HeaderMap,
    memory_id: RoutePath<String>,
    request: Result<Json<DashboardMemoryLifecycleRequest>, JsonRejection>,
) -> AxumResponse {
    memory_lifecycle(
        state,
        headers,
        memory_id,
        request,
        DashboardMemoryLifecycleAction::Expire,
    )
    .await
}

async fn reject_memory(
    state: State<DashboardState>,
    headers: HeaderMap,
    memory_id: RoutePath<String>,
    request: Result<Json<DashboardMemoryLifecycleRequest>, JsonRejection>,
) -> AxumResponse {
    memory_lifecycle(
        state,
        headers,
        memory_id,
        request,
        DashboardMemoryLifecycleAction::Reject,
    )
    .await
}

async fn delete_memory(
    state: State<DashboardState>,
    headers: HeaderMap,
    memory_id: RoutePath<String>,
    request: Result<Json<DashboardMemoryLifecycleRequest>, JsonRejection>,
) -> AxumResponse {
    memory_lifecycle(
        state,
        headers,
        memory_id,
        request,
        DashboardMemoryLifecycleAction::Delete,
    )
    .await
}

async fn memory_lifecycle(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    RoutePath(memory_id): RoutePath<String>,
    request: Result<Json<DashboardMemoryLifecycleRequest>, JsonRejection>,
    action: DashboardMemoryLifecycleAction,
) -> AxumResponse {
    if let Some(response) = authorize_dashboard_mutation(&state, &headers) {
        return response;
    }
    let Ok(memory_id) = memory_id.parse::<MemoryId>() else {
        return secure_response(invalid_dashboard_identifier(), &state);
    };
    let Ok(Json(request)) = request else {
        return secure_response(invalid_dashboard_json(), &state);
    };
    let Some(expected_response_revision) = request.expected_revision.checked_add(1) else {
        return secure_response(invalid_dashboard_command(), &state);
    };
    if !valid_api_version(&request.api_version)
        || !valid_memory_workspace_identity(&request.workspace_identity)
    {
        return secure_response(invalid_dashboard_command(), &state);
    }
    let Ok(_permit) = Arc::clone(&state.command_permit).try_acquire_owned() else {
        return secure_response(command_in_progress(), &state);
    };
    let response = match dashboard_connection(&state) {
        Ok(connection) => {
            let memory_id = memory_id.to_string();
            match fetch_memory_from_daemon(
                &state.client,
                &connection,
                &request.workspace_identity,
                &memory_id,
            )
            .await
            {
                Ok(current)
                    if valid_memory_response(
                        &current,
                        Some(&memory_id),
                        &request.workspace_identity,
                    ) =>
                {
                    let expected_status = action.expected_status();
                    if current.revision == expected_response_revision
                        && current.status == expected_status
                    {
                        Json(current).into_response()
                    } else if current.revision != request.expected_revision
                        || !memory_lifecycle_source_allowed(action, current.status)
                    {
                        dashboard_state_conflict("memory lifecycle")
                    } else {
                        let command = MemoryLifecycleRequest {
                            api_version: API_VERSION.to_owned(),
                            expected_revision: request.expected_revision,
                        };
                        let operation = action.path_segment();
                        let path = format!("/v1/memories/{memory_id}/{operation}");
                        match post_to_daemon::<_, MemoryResponse>(
                            &state.client,
                            &connection,
                            &path,
                            &command,
                        )
                        .await
                        {
                            Ok(response)
                                if valid_memory_response(
                                    &response,
                                    Some(&memory_id),
                                    &request.workspace_identity,
                                ) && response.revision == expected_response_revision
                                    && response.status == expected_status =>
                            {
                                Json(response).into_response()
                            }
                            Ok(_) => dashboard_protocol_error("memory lifecycle"),
                            Err(error) => dashboard_backend_error(&error, "memory lifecycle"),
                        }
                    }
                }
                Ok(_) => dashboard_protocol_error("memory lifecycle preflight"),
                Err(error) => dashboard_backend_error(&error, "memory lifecycle preflight"),
            }
        }
        Err(()) => dashboard_connection_error(),
    };
    secure_response(response, &state)
}

async fn extension_list(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    request: Result<Json<DashboardExtensionReadRequest>, JsonRejection>,
) -> AxumResponse {
    if let Some(response) = authorize_dashboard_mutation(&state, &headers) {
        return response;
    }
    let Ok(Json(request)) = request else {
        return secure_response(invalid_dashboard_json(), &state);
    };
    if !valid_api_version(&request.api_version) {
        return secure_response(invalid_dashboard_command(), &state);
    }
    let Ok(_permit) = Arc::clone(&state.detail_permit).try_acquire_owned() else {
        return secure_response(detail_in_progress(), &state);
    };
    let response = match dashboard_connection(&state) {
        Ok(connection) => {
            match fetch::<ExtensionsResponse>(&state.client, &connection, "/v1/extensions").await {
                Ok(response) if valid_extensions_response(&response) => {
                    Json(response).into_response()
                }
                Ok(_) => dashboard_protocol_error("extension list"),
                Err(error) => dashboard_backend_error(&error, "extension list"),
            }
        }
        Err(()) => dashboard_connection_error(),
    };
    secure_response(response, &state)
}

async fn extension_detail(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    RoutePath(extension_id): RoutePath<String>,
    request: Result<Json<DashboardExtensionReadRequest>, JsonRejection>,
) -> AxumResponse {
    if let Some(response) = authorize_dashboard_mutation(&state, &headers) {
        return response;
    }
    let Ok(extension_id) = extension_id.parse::<ExtensionId>() else {
        return secure_response(invalid_dashboard_identifier(), &state);
    };
    let Ok(Json(request)) = request else {
        return secure_response(invalid_dashboard_json(), &state);
    };
    if !valid_api_version(&request.api_version) {
        return secure_response(invalid_dashboard_command(), &state);
    }
    let Ok(_permit) = Arc::clone(&state.detail_permit).try_acquire_owned() else {
        return secure_response(detail_in_progress(), &state);
    };
    let response = match dashboard_connection(&state) {
        Ok(connection) => {
            let extension_id = extension_id.to_string();
            match fetch_extension_from_daemon(&state.client, &connection, &extension_id).await {
                Ok(response) if valid_extension_response(&response, Some(&extension_id)) => {
                    Json(response).into_response()
                }
                Ok(_) => dashboard_protocol_error("extension detail"),
                Err(error) => dashboard_backend_error(&error, "extension detail"),
            }
        }
        Err(()) => dashboard_connection_error(),
    };
    secure_response(response, &state)
}

async fn enable_extension(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    RoutePath(extension_id): RoutePath<String>,
    request: Result<Json<DashboardEnableExtensionRequest>, JsonRejection>,
) -> AxumResponse {
    if let Some(response) = authorize_dashboard_mutation(&state, &headers) {
        return response;
    }
    let Ok(extension_id) = extension_id.parse::<ExtensionId>() else {
        return secure_response(invalid_dashboard_identifier(), &state);
    };
    let Ok(Json(request)) = request else {
        return secure_response(invalid_dashboard_json(), &state);
    };
    let Some(expected_response_revision) = request.expected_revision.checked_add(1) else {
        return secure_response(invalid_dashboard_command(), &state);
    };
    if !valid_api_version(&request.api_version) {
        return secure_response(invalid_dashboard_command(), &state);
    }
    let Ok(_permit) = Arc::clone(&state.command_permit).try_acquire_owned() else {
        return secure_response(command_in_progress(), &state);
    };
    let response = match dashboard_connection(&state) {
        Ok(connection) => {
            let extension_id = extension_id.to_string();
            match fetch_extension_from_daemon(&state.client, &connection, &extension_id).await {
                Ok(current) if valid_extension_response(&current, Some(&extension_id)) => {
                    if !valid_extension_enable_request(&request, &current) {
                        invalid_dashboard_command()
                    } else if current.revision == expected_response_revision
                        && current.status == ExtensionStatusResponse::Enabled
                        && extension_grant_matches_request(&current, &request)
                    {
                        Json(current).into_response()
                    } else if current.revision != request.expected_revision
                        || !matches!(
                            current.status,
                            ExtensionStatusResponse::Installed
                                | ExtensionStatusResponse::Disabled
                                | ExtensionStatusResponse::Failed
                        )
                    {
                        dashboard_state_conflict("extension enable")
                    } else {
                        let command = EnableExtensionRequest {
                            api_version: API_VERSION.to_owned(),
                            expected_revision: request.expected_revision,
                            capability_ids: request.capability_ids.clone(),
                            mounts: request.mounts.clone(),
                            network_destinations: request.network_destinations.clone(),
                            secret_references: request.secret_references.clone(),
                            allow_process_spawn: request.allow_process_spawn,
                        };
                        let path = format!("/v1/extensions/{extension_id}/enable");
                        match post_to_daemon::<_, ExtensionResponse>(
                            &state.client,
                            &connection,
                            &path,
                            &command,
                        )
                        .await
                        {
                            Ok(response)
                                if valid_extension_response(&response, Some(&extension_id))
                                    && response.status == ExtensionStatusResponse::Enabled
                                    && response.revision == expected_response_revision
                                    && same_extension_manifest_projection(&current, &response)
                                    && extension_grant_matches_request(&response, &request) =>
                            {
                                Json(response).into_response()
                            }
                            Ok(_) => dashboard_protocol_error("extension enable"),
                            Err(error) => dashboard_backend_error(&error, "extension enable"),
                        }
                    }
                }
                Ok(_) => dashboard_protocol_error("extension enable preflight"),
                Err(error) => dashboard_backend_error(&error, "extension enable preflight"),
            }
        }
        Err(()) => dashboard_connection_error(),
    };
    secure_response(response, &state)
}

async fn disable_extension(
    state: State<DashboardState>,
    headers: HeaderMap,
    extension_id: RoutePath<String>,
    request: Result<Json<DashboardExtensionLifecycleRequest>, JsonRejection>,
) -> AxumResponse {
    extension_lifecycle(
        state,
        headers,
        extension_id,
        request,
        DashboardExtensionLifecycleAction::Disable,
    )
    .await
}

async fn revoke_extension(
    state: State<DashboardState>,
    headers: HeaderMap,
    extension_id: RoutePath<String>,
    request: Result<Json<DashboardExtensionLifecycleRequest>, JsonRejection>,
) -> AxumResponse {
    extension_lifecycle(
        state,
        headers,
        extension_id,
        request,
        DashboardExtensionLifecycleAction::Revoke,
    )
    .await
}

async fn extension_lifecycle(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    RoutePath(extension_id): RoutePath<String>,
    request: Result<Json<DashboardExtensionLifecycleRequest>, JsonRejection>,
    action: DashboardExtensionLifecycleAction,
) -> AxumResponse {
    if let Some(response) = authorize_dashboard_mutation(&state, &headers) {
        return response;
    }
    let Ok(extension_id) = extension_id.parse::<ExtensionId>() else {
        return secure_response(invalid_dashboard_identifier(), &state);
    };
    let Ok(Json(request)) = request else {
        return secure_response(invalid_dashboard_json(), &state);
    };
    let Some(expected_response_revision) = request.expected_revision.checked_add(1) else {
        return secure_response(invalid_dashboard_command(), &state);
    };
    if !valid_api_version(&request.api_version) {
        return secure_response(invalid_dashboard_command(), &state);
    }
    let Ok(_permit) = Arc::clone(&state.command_permit).try_acquire_owned() else {
        return secure_response(command_in_progress(), &state);
    };
    let response = match dashboard_connection(&state) {
        Ok(connection) => {
            let extension_id = extension_id.to_string();
            match fetch_extension_from_daemon(&state.client, &connection, &extension_id).await {
                Ok(current) if valid_extension_response(&current, Some(&extension_id)) => {
                    let expected_status = action.expected_status();
                    if current.revision == expected_response_revision
                        && current.status == expected_status
                    {
                        Json(current).into_response()
                    } else if current.revision != request.expected_revision
                        || !action.accepts_source(current.status)
                    {
                        dashboard_state_conflict("extension lifecycle")
                    } else {
                        let command = ExtensionLifecycleRequest {
                            api_version: API_VERSION.to_owned(),
                            expected_revision: request.expected_revision,
                        };
                        let operation = action.path_segment();
                        let path = format!("/v1/extensions/{extension_id}/{operation}");
                        match post_to_daemon::<_, ExtensionResponse>(
                            &state.client,
                            &connection,
                            &path,
                            &command,
                        )
                        .await
                        {
                            Ok(response)
                                if valid_extension_response(&response, Some(&extension_id))
                                    && response.status == expected_status
                                    && response.revision == expected_response_revision
                                    && same_extension_manifest_projection(&current, &response) =>
                            {
                                Json(response).into_response()
                            }
                            Ok(_) => dashboard_protocol_error("extension lifecycle"),
                            Err(error) => dashboard_backend_error(&error, "extension lifecycle"),
                        }
                    }
                }
                Ok(_) => dashboard_protocol_error("extension lifecycle preflight"),
                Err(error) => dashboard_backend_error(&error, "extension lifecycle preflight"),
            }
        }
        Err(()) => dashboard_connection_error(),
    };
    secure_response(response, &state)
}

async fn method_not_allowed(State(state): State<DashboardState>) -> AxumResponse {
    secure_response(
        dashboard_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "dashboard_method_not_allowed",
            "This dashboard route does not accept that method.",
        ),
        &state,
    )
}

async fn not_found(State(state): State<DashboardState>) -> AxumResponse {
    secure_response(
        dashboard_error(
            StatusCode::NOT_FOUND,
            "dashboard_not_found",
            "This temporary dashboard route does not exist.",
        ),
        &state,
    )
}

async fn fetch_snapshot(
    client: &Client,
    connection: &LocalConnectionInfo,
) -> Result<DashboardSnapshot, CliError> {
    let generated_at_ms = current_epoch_milliseconds()?;
    let usage_to_ms = i64::try_from(generated_at_ms)
        .map_err(|_| CliError::Protocol("dashboard clock exceeds signed epoch time".to_owned()))?;
    let usage_from_ms = usage_to_ms
        .checked_sub(DASHBOARD_USAGE_DAYS * USAGE_DAY_MS)
        .ok_or_else(|| CliError::Protocol("dashboard usage range underflowed".to_owned()))?;
    // A dashboard refresh is one control-plane reader. Keep its projections serial so the
    // refresh cannot exceed the runtime's reserved reader capacity by fanning out internally.
    let status = dashboard_snapshot_source(
        fetch::<AdminStatusResponse>(client, connection, "/v1/admin/status").await,
        "status",
    )?;
    let doctor = dashboard_snapshot_source(
        fetch::<DoctorResponse>(client, connection, "/v1/admin/doctor").await,
        "doctor",
    )?;
    let sessions = dashboard_snapshot_source(
        fetch::<SessionsResponse>(client, connection, "/v1/sessions?limit=20").await,
        "sessions",
    )?;
    let approvals = dashboard_snapshot_source(
        fetch::<PendingApprovalsResponse>(client, connection, "/v1/approvals").await,
        "approvals",
    )?;
    let schedules = dashboard_snapshot_source(
        fetch::<SchedulesResponse>(client, connection, "/v1/schedules").await,
        "schedules",
    )?;
    let usage_query = [
        ("fromMs", usage_from_ms.to_string()),
        ("toMs", usage_to_ms.to_string()),
    ];
    let usage = dashboard_snapshot_source(
        fetch_with_query::<_, AdminUsageReportResponse>(
            client,
            connection,
            "/v1/admin/usage",
            &usage_query,
        )
        .await,
        "usage",
    )?;
    let snapshot = DashboardSnapshot {
        api_version: API_VERSION.to_owned(),
        generated_at_ms,
        status,
        doctor,
        sessions,
        approvals,
        schedules,
        usage,
    };
    if !valid_api_version(&snapshot.status.api_version)
        || !valid_api_version(&snapshot.doctor.api_version)
        || !valid_api_version(&snapshot.sessions.api_version)
        || !valid_api_version(&snapshot.approvals.api_version)
        || !valid_api_version(&snapshot.schedules.api_version)
        || !valid_admin_usage_report(&snapshot.usage, usage_from_ms, usage_to_ms)
    {
        return Err(CliError::Protocol(
            "dashboard source response uses an unsupported API version".to_owned(),
        ));
    }
    let mut schedule_ids = BTreeSet::new();
    if snapshot.schedules.schedules.len() > MAXIMUM_DASHBOARD_SCHEDULES
        || !snapshot.schedules.schedules.iter().all(|schedule| {
            schedule_ids.insert(schedule.schedule_id.as_str())
                && valid_schedule_response(schedule, &schedule.schedule_id)
        })
    {
        return Err(CliError::Protocol(
            "dashboard schedule projection is invalid or exceeds its bound".to_owned(),
        ));
    }
    Ok(snapshot)
}

fn dashboard_snapshot_source<T>(result: Result<T, CliError>, source: &str) -> Result<T, CliError> {
    result.map_err(|error| {
        CliError::Protocol(format!(
            "dashboard {source} projection request failed: {error}"
        ))
    })
}

async fn fetch<T: DeserializeOwned>(
    client: &Client,
    connection: &LocalConnectionInfo,
    path: &str,
) -> Result<T, CliError> {
    let response = authorized(
        client.get(format!("{}{path}", connection.base_url)),
        connection,
    )
    .send()
    .await?;
    decode_dashboard(response).await
}

async fn fetch_with_query<Q: Serialize + ?Sized, T: DeserializeOwned>(
    client: &Client,
    connection: &LocalConnectionInfo,
    path: &str,
    query: &Q,
) -> Result<T, CliError> {
    let response = authorized(
        client
            .get(format!("{}{path}", connection.base_url))
            .query(query),
        connection,
    )
    .send()
    .await?;
    decode_dashboard(response).await
}

async fn fetch_memories_from_daemon(
    client: &Client,
    connection: &LocalConnectionInfo,
    workspace_identity: &str,
    include_deleted: bool,
) -> Result<MemoriesResponse, CliError> {
    fetch_with_query(
        client,
        connection,
        "/v1/memories",
        &[
            ("workspaceIdentity", workspace_identity.to_owned()),
            ("includeDeleted", include_deleted.to_string()),
        ],
    )
    .await
}

async fn fetch_memory_search_from_daemon(
    client: &Client,
    connection: &LocalConnectionInfo,
    request: &DashboardMemorySearchRequest,
) -> Result<MemorySearchResponse, CliError> {
    fetch_with_query(
        client,
        connection,
        "/v1/memories/search",
        &[
            ("workspaceIdentity", request.workspace_identity.clone()),
            ("query", request.query.clone()),
            (
                "maximumSensitivity",
                memory_sensitivity_name(request.maximum_sensitivity).to_owned(),
            ),
            ("limit", request.limit.to_string()),
        ],
    )
    .await
}

async fn fetch_memory_from_daemon(
    client: &Client,
    connection: &LocalConnectionInfo,
    workspace_identity: &str,
    memory_id: &str,
) -> Result<MemoryResponse, CliError> {
    let path = format!("/v1/memories/{memory_id}");
    fetch_with_query(
        client,
        connection,
        &path,
        &[("workspaceIdentity", workspace_identity)],
    )
    .await
}

async fn fetch_extension_from_daemon(
    client: &Client,
    connection: &LocalConnectionInfo,
    extension_id: &str,
) -> Result<ExtensionResponse, CliError> {
    fetch(
        client,
        connection,
        &format!("/v1/extensions/{extension_id}"),
    )
    .await
}

async fn post_to_daemon<Q: Serialize + ?Sized, T: DeserializeOwned>(
    client: &Client,
    connection: &LocalConnectionInfo,
    path: &str,
    command: &Q,
) -> Result<T, CliError> {
    let response = authorized(
        client.post(format!("{}{path}", connection.base_url)),
        connection,
    )
    .json(command)
    .send()
    .await?;
    decode_dashboard(response).await
}

async fn decode_dashboard<T: DeserializeOwned>(response: reqwest::Response) -> Result<T, CliError> {
    super::decode(response).await
}

fn authorize_dashboard_read(state: &DashboardState, headers: &HeaderMap) -> Option<AxumResponse> {
    (!valid_dashboard_request_origin(state, headers) || !valid_dashboard_token(state, headers))
        .then(|| {
            secure_response(
                dashboard_error(
                    StatusCode::UNAUTHORIZED,
                    "dashboard_unauthorized",
                    "The temporary dashboard capability is missing or invalid.",
                ),
                state,
            )
        })
}

fn authorize_dashboard_mutation(
    state: &DashboardState,
    headers: &HeaderMap,
) -> Option<AxumResponse> {
    if !valid_dashboard_request_origin(state, headers) || !valid_dashboard_token(state, headers) {
        return Some(secure_response(
            dashboard_error(
                StatusCode::UNAUTHORIZED,
                "dashboard_unauthorized",
                "The temporary dashboard capability is missing or invalid.",
            ),
            state,
        ));
    }
    (!valid_dashboard_mutation_origin(state, headers)).then(|| {
        secure_response(
            dashboard_error(
                StatusCode::FORBIDDEN,
                "dashboard_mutation_origin_required",
                "Dashboard commands require the exact loopback browser origin.",
            ),
            state,
        )
    })
}

fn dashboard_connection(state: &DashboardState) -> Result<LocalConnectionInfo, ()> {
    load_connection(&state.home)
        .ok()
        .filter(|connection| valid_api_version(&connection.api_version))
        .ok_or(())
}

fn dashboard_connection_error() -> AxumResponse {
    dashboard_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "dashboard_connection_unavailable",
        "The private daemon connection descriptor is unavailable or invalid.",
    )
}

fn active_task_id(
    status: &SessionStatusResponse,
    timeline: &TimelinePageResponse,
) -> Option<String> {
    let active_turn_id = status.active_turn_id.as_deref()?;
    timeline.events.iter().rev().find_map(|event| {
        (event.event_type == "task.created"
            && event.payload["turn_id"].as_str() == Some(active_turn_id)
            && event.aggregate_id.parse::<TaskId>().is_ok())
        .then(|| event.aggregate_id.clone())
    })
}

fn valid_dashboard_request_origin(state: &DashboardState, headers: &HeaderMap) -> bool {
    headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        == Some(state.authority.as_ref())
        && headers
            .get(header::ORIGIN)
            .is_none_or(|value| value.to_str().ok() == Some(state.origin.as_ref()))
}

fn valid_dashboard_mutation_origin(state: &DashboardState, headers: &HeaderMap) -> bool {
    headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        == Some(state.origin.as_ref())
}

fn valid_dashboard_token(state: &DashboardState, headers: &HeaderMap) -> bool {
    let Some(encoded) = headers
        .get(DASHBOARD_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() <= 64)
    else {
        return false;
    };
    let Ok(decoded) = URL_SAFE_NO_PAD.decode(encoded) else {
        return false;
    };
    decoded.len() == state.token.len() && state.token.ct_eq(decoded.as_slice()).unwrap_u8() == 1
}

fn valid_api_version(value: &str) -> bool {
    value == API_VERSION
}

fn valid_admin_usage_report(
    report: &AdminUsageReportResponse,
    expected_from_ms: i64,
    expected_to_ms: i64,
) -> bool {
    if !valid_api_version(&report.api_version)
        || report.from_ms != expected_from_ms
        || report.to_ms != expected_to_ms
        || report.buckets.len() > 31
        || [report.from_ms, report.to_ms].iter().any(|value| {
            u64::try_from(*value).map_or(true, |value| value > MAXIMUM_JAVASCRIPT_SAFE_INTEGER)
        })
    {
        return false;
    }
    let mut previous_start = None;
    let mut totals = [0_u64; 12];
    for bucket in &report.buckets {
        let Some(day_end_ms) = bucket.bucket_start_ms.checked_add(USAGE_DAY_MS) else {
            return false;
        };
        let values = [
            bucket.completed_runs,
            bucket.succeeded_runs,
            bucket.failed_runs,
            bucket.cancelled_runs,
            bucket.used_model_calls,
            bucket.used_tool_calls,
            bucket.used_delegated_runs,
            bucket.used_retries,
            bucket.used_input_tokens,
            bucket.used_output_tokens,
            bucket.used_cost_microunits,
            bucket.used_output_bytes,
        ];
        if bucket.bucket_start_ms < 0
            || bucket.bucket_start_ms % USAGE_DAY_MS != 0
            || day_end_ms <= report.from_ms
            || bucket.bucket_start_ms >= report.to_ms
            || bucket.bucket_end_ms != day_end_ms.min(report.to_ms)
            || bucket.completed_runs == 0
            || bucket
                .succeeded_runs
                .checked_add(bucket.failed_runs)
                .and_then(|value| value.checked_add(bucket.cancelled_runs))
                != Some(bucket.completed_runs)
            || previous_start.is_some_and(|previous| previous >= bucket.bucket_start_ms)
            || [bucket.bucket_start_ms, bucket.bucket_end_ms]
                .iter()
                .any(|value| {
                    u64::try_from(*value)
                        .map_or(true, |value| value > MAXIMUM_JAVASCRIPT_SAFE_INTEGER)
                })
            || values
                .iter()
                .any(|value| *value > MAXIMUM_JAVASCRIPT_SAFE_INTEGER)
        {
            return false;
        }
        for (total, value) in totals.iter_mut().zip(values) {
            let Some(sum) = total.checked_add(value) else {
                return false;
            };
            if sum > MAXIMUM_JAVASCRIPT_SAFE_INTEGER {
                return false;
            }
            *total = sum;
        }
        previous_start = Some(bucket.bucket_start_ms);
    }
    true
}

fn valid_idempotency_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_IDEMPOTENCY_KEY_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_sha256_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_reconciliation_evidence(value: &serde_json::Value) -> bool {
    value.as_object().is_some_and(|object| !object.is_empty())
        && serde_json::to_vec(value)
            .is_ok_and(|encoded| encoded.len() <= MAXIMUM_EFFECT_OUTCOME_DETAILS_BYTES)
}

fn valid_dashboard_schedule_create_request(request: &DashboardCreateScheduleRequest) -> bool {
    let Ok(session_id) = request.session_id.parse::<SessionId>() else {
        return false;
    };
    valid_api_version(&request.api_version)
        && valid_canonical_schedule_id(&request.schedule_id)
        && session_id.to_string() == request.session_id
        && request.prompt.len() <= MAXIMUM_DASHBOARD_SCHEDULE_PROMPT_BYTES
        && validate_schedule_definition(ScheduleDefinition {
            name: &request.name,
            prompt: &request.prompt,
            cron_expression: &request.cron_expression,
            timezone: &request.timezone,
            misfire_grace_ms: request.misfire_grace_ms,
            approval_required_actions_allowed: request.allow_approval_required_action,
        })
        .is_ok()
}

fn valid_canonical_schedule_id(value: &str) -> bool {
    value.parse::<ScheduleId>().is_ok_and(|schedule_id| {
        schedule_id.to_string() == value && schedule_id.as_uuid().get_version_num() == 7
    })
}

fn schedule_matches_create_request(
    response: &ScheduleResponse,
    request: &DashboardCreateScheduleRequest,
) -> bool {
    response.schedule_id == request.schedule_id
        && response.session_id == request.session_id
        && response.name == request.name
        && response.prompt == request.prompt
        && response.cron_expression == request.cron_expression
        && response.timezone == request.timezone
        && response.missed_run_policy == request.missed_run_policy
        && response.overlap_policy == request.overlap_policy
        && response.misfire_grace_ms == request.misfire_grace_ms
        && response.allow_approval_required_action == request.allow_approval_required_action
}

fn valid_schedule_response(response: &ScheduleResponse, expected_schedule_id: &str) -> bool {
    let definition_valid = validate_schedule_definition(ScheduleDefinition {
        name: &response.name,
        prompt: &response.prompt,
        cron_expression: &response.cron_expression,
        timezone: &response.timezone,
        misfire_grace_ms: response.misfire_grace_ms,
        approval_required_actions_allowed: response.allow_approval_required_action,
    })
    .is_ok();
    let lifecycle_valid = match response.status {
        ScheduleStatusResponse::Active | ScheduleStatusResponse::Paused => {
            response.next_due_at_ms.is_some_and(|due| due >= 0)
        }
        ScheduleStatusResponse::Cancelled => response.next_due_at_ms.is_none(),
    };
    valid_api_version(&response.api_version)
        && response.schedule_id == expected_schedule_id
        && valid_canonical_schedule_id(&response.schedule_id)
        && response.session_id.parse::<SessionId>().is_ok()
        && definition_valid
        && lifecycle_valid
        && response.created_at_ms >= 0
        && response.updated_at_ms >= response.created_at_ms
}

fn valid_schedule_runs_response(
    response: &ScheduleRunsResponse,
    expected_schedule_id: &str,
    limit: usize,
) -> bool {
    if !valid_api_version(&response.api_version)
        || response.schedule_id != expected_schedule_id
        || !valid_canonical_schedule_id(&response.schedule_id)
        || response.runs.len() > limit
    {
        return false;
    }
    if !response.runs.windows(2).all(|pair| {
        pair[0].scheduled_for_ms > pair[1].scheduled_for_ms
            || pair[0].scheduled_for_ms == pair[1].scheduled_for_ms
                && pair[0].schedule_run_id > pair[1].schedule_run_id
    }) {
        return false;
    }
    let mut identifiers = BTreeSet::new();
    response.runs.iter().all(|run| {
        identifiers.insert(run.schedule_run_id.as_str())
            && valid_schedule_run_response(run, expected_schedule_id)
    })
}

fn valid_schedule_run_response(run: &ScheduleRunResponse, expected_schedule_id: &str) -> bool {
    let completion_shape_valid = match run.status {
        ScheduleRunStatusResponse::Claimed => {
            run.inbox_entry_id.is_none()
                && run.reason.is_none()
                && run.completed_at_ms.is_none()
                && run.intent == ScheduleRunIntentResponse::Fire
        }
        ScheduleRunStatusResponse::Admitted => {
            run.inbox_entry_id
                .as_deref()
                .is_some_and(|value| value.parse::<InboxEntryId>().is_ok())
                && run.reason.is_none()
                && run.completed_at_ms.is_some()
                && run.intent == ScheduleRunIntentResponse::Fire
        }
        ScheduleRunStatusResponse::Skipped => {
            run.inbox_entry_id.is_none()
                && valid_schedule_run_reason(run.reason.as_deref())
                && run.completed_at_ms.is_some()
                && matches!(
                    run.intent,
                    ScheduleRunIntentResponse::SkipMisfire | ScheduleRunIntentResponse::SkipOverlap
                )
        }
        ScheduleRunStatusResponse::Failed => {
            run.inbox_entry_id.is_none()
                && valid_schedule_run_reason(run.reason.as_deref())
                && run.completed_at_ms.is_some()
                && run.intent == ScheduleRunIntentResponse::Fire
        }
    };
    run.schedule_run_id.parse::<ScheduleRunId>().is_ok()
        && run.schedule_id == expected_schedule_id
        && valid_canonical_schedule_id(&run.schedule_id)
        && run.scheduled_for_ms >= 0
        && run.created_at_ms >= 0
        && run
            .completed_at_ms
            .is_none_or(|value| value >= run.created_at_ms)
        && completion_shape_valid
}

fn valid_schedule_run_reason(reason: Option<&str>) -> bool {
    reason.is_some_and(|reason| {
        !reason.is_empty()
            && reason.len() <= MAXIMUM_SCHEDULE_RUN_REASON_BYTES
            && !reason.chars().any(char::is_control)
    })
}

fn valid_memories_response(
    response: &MemoriesResponse,
    expected_workspace: &str,
    include_deleted: bool,
) -> bool {
    if !valid_api_version(&response.api_version)
        || response.memories.len() > MAXIMUM_DASHBOARD_MEMORIES
        || !include_deleted
            && response
                .memories
                .iter()
                .any(|memory| memory.status == MemoryStatusResponse::Deleted)
        || !response.memories.windows(2).all(|pair| {
            pair[0].created_at_ms < pair[1].created_at_ms
                || pair[0].created_at_ms == pair[1].created_at_ms
                    && pair[0].memory_id < pair[1].memory_id
        })
    {
        return false;
    }
    let mut identifiers = BTreeSet::new();
    response.memories.iter().all(|memory| {
        identifiers.insert(memory.memory_id.as_str())
            && valid_memory_response(memory, None, expected_workspace)
    })
}

fn valid_memory_search_response(
    response: &MemorySearchResponse,
    expected_workspace: &str,
    maximum_sensitivity: MemorySensitivityCommand,
    limit: usize,
) -> bool {
    if !valid_api_version(&response.api_version) || response.hits.len() > limit {
        return false;
    }
    let mut identifiers = BTreeSet::new();
    response.hits.iter().all(|hit| {
        hit.lexical_rank.is_finite()
            && hit.memory.status == MemoryStatusResponse::Active
            && memory_sensitivity_rank(hit.memory.sensitivity)
                <= memory_sensitivity_rank(maximum_sensitivity)
            && identifiers.insert(hit.memory.memory_id.as_str())
            && valid_memory_response(&hit.memory, None, expected_workspace)
    })
}

#[allow(clippy::too_many_lines)]
fn valid_memory_response(
    response: &MemoryResponse,
    expected_memory_id: Option<&str>,
    expected_workspace: &str,
) -> bool {
    if !valid_api_version(&response.api_version)
        || expected_memory_id.is_some_and(|expected| response.memory_id != expected)
        || response.memory_id.parse::<MemoryId>().is_err()
        || response.principal_id.parse::<PrincipalId>().is_err()
        || response.workspace_identity != expected_workspace
        || !valid_memory_workspace_identity(&response.workspace_identity)
        || response.confidence_basis_points > 10_000
        || response.created_at_ms < 0
        || response.last_verified_at_ms < response.created_at_ms
        || response.revisions.is_empty()
        || response.revisions.len() > MAXIMUM_DASHBOARD_MEMORY_REVISIONS
        || response.status == MemoryStatusResponse::Proposed
            && (response.revision != 0 || response.revisions.len() != 1)
    {
        return false;
    }
    let mut identifiers = BTreeSet::new();
    let mut active_revisions = 0_usize;
    for (index, revision) in response.revisions.iter().enumerate() {
        let Some(expected_ordinal) = u64::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
        else {
            return false;
        };
        if revision.ordinal != expected_ordinal
            || revision.revision_id.parse::<MemoryRevisionId>().is_err()
            || !identifiers.insert(revision.revision_id.as_str())
            || !valid_sha256_digest(&revision.content_digest)
            || revision.confidence_basis_points > 10_000
            || revision.created_at_ms < 0
            || revision.last_verified_at_ms < revision.created_at_ms
            || revision.sources.is_empty()
            || revision.sources.len() > MAXIMUM_MEMORY_SOURCES
            || (revision.status == MemoryStatusResponse::Deleted) != revision.content.is_none()
            || revision.content.as_deref().is_some_and(|content| {
                content.is_empty()
                    || content.len() > 65_536
                    || content.contains('\0')
                    || sha256_digest(content.as_bytes()) != revision.content_digest
            })
        {
            return false;
        }
        let expected_superseded = index
            .checked_sub(1)
            .map(|previous| response.revisions[previous].revision_id.as_str());
        if revision.supersedes_revision_id.as_deref() != expected_superseded {
            return false;
        }
        let mut locators = BTreeSet::new();
        if !revision.sources.iter().all(|source| {
            !source.locator.is_empty()
                && source.locator.len() <= MAXIMUM_MEMORY_SOURCE_LOCATOR_BYTES
                && source.locator.trim() == source.locator
                && !source.locator.chars().any(char::is_control)
                && valid_sha256_digest(&source.digest)
                && locators.insert(source.locator.as_str())
        }) {
            return false;
        }
        active_revisions += usize::from(revision.status == MemoryStatusResponse::Active);
    }
    let Some(newest) = response.revisions.last() else {
        return false;
    };
    let prior_statuses_valid = response
        .revisions
        .iter()
        .take(response.revisions.len().saturating_sub(1))
        .all(|revision| {
            matches!(
                revision.status,
                MemoryStatusResponse::Superseded | MemoryStatusResponse::Deleted
            )
        });
    response.status == newest.status
        && response.confidence_basis_points == newest.confidence_basis_points
        && response.sensitivity == newest.sensitivity
        && response.created_at_ms == response.revisions[0].created_at_ms
        && response.last_verified_at_ms == newest.last_verified_at_ms
        && active_revisions <= 1
        && (response.status == MemoryStatusResponse::Active) == (active_revisions == 1)
        && prior_statuses_valid
}

fn valid_dashboard_memory_content(content: &str) -> bool {
    !content.is_empty()
        && content.len() <= MAXIMUM_DASHBOARD_MEMORY_CONTENT_BYTES
        && !content.contains('\0')
}

fn dashboard_memory_source_locator(idempotency_key: &str) -> String {
    let material = format!("mealy.dashboard-memory-command.v1:{idempotency_key}");
    format!(
        "{DASHBOARD_MEMORY_SOURCE_PREFIX}{}",
        sha256_digest(material.as_bytes())
    )
}

fn memories_with_source_locator<'a>(
    response: &'a MemoriesResponse,
    locator: &str,
) -> Vec<&'a MemoryResponse> {
    response
        .memories
        .iter()
        .filter(|memory| memory_has_source_locator(memory, locator))
        .collect()
}

fn memory_has_source_locator(memory: &MemoryResponse, locator: &str) -> bool {
    memory.revisions.iter().any(|revision| {
        revision
            .sources
            .iter()
            .any(|source| source.locator == locator)
    })
}

fn memory_matches_proposal(
    memory: &MemoryResponse,
    request: &DashboardProposeMemoryRequest,
    source_locator: &str,
    source_digest: &str,
) -> bool {
    memory.category == request.category
        && memory.revisions.first().is_some_and(|revision| {
            revision.content_digest == source_digest
                && revision.confidence_basis_points == request.confidence_basis_points
                && revision.sensitivity == request.sensitivity
                && revision.retention == request.retention
                && revision.sources.iter().any(|source| {
                    source.locator == source_locator && source.digest == source_digest
                })
        })
}

fn memory_matches_correction(
    memory: &MemoryResponse,
    request: &DashboardCorrectMemoryRequest,
    source_locator: &str,
    source_digest: &str,
) -> bool {
    memory.revisions.last().is_some_and(|revision| {
        revision.status == MemoryStatusResponse::Active
            && revision.content_digest == source_digest
            && revision.confidence_basis_points == request.confidence_basis_points
            && revision.sensitivity == request.sensitivity
            && revision.retention == request.retention
            && revision
                .sources
                .iter()
                .any(|source| source.locator == source_locator && source.digest == source_digest)
    })
}

fn memory_revision_has_status(
    memory: &MemoryResponse,
    revision_id: &str,
    status: MemoryStatusResponse,
) -> bool {
    memory
        .revisions
        .iter()
        .any(|revision| revision.revision_id == revision_id && revision.status == status)
}

const fn memory_lifecycle_source_allowed(
    action: DashboardMemoryLifecycleAction,
    status: MemoryStatusResponse,
) -> bool {
    match action {
        DashboardMemoryLifecycleAction::Expire => matches!(status, MemoryStatusResponse::Active),
        DashboardMemoryLifecycleAction::Reject => matches!(status, MemoryStatusResponse::Proposed),
        DashboardMemoryLifecycleAction::Delete => !matches!(status, MemoryStatusResponse::Deleted),
    }
}

fn valid_task_response(response: &TaskResponse, expected_task_id: &str) -> bool {
    let usage = response.usage;
    let usage_values = [
        usage.used_model_calls,
        usage.reserved_model_calls,
        usage.used_tool_calls,
        usage.reserved_tool_calls,
        usage.used_delegated_runs,
        usage.reserved_delegated_runs,
        usage.used_retries,
        usage.used_input_tokens,
        usage.reserved_input_tokens,
        usage.used_output_tokens,
        usage.reserved_output_tokens,
        usage.used_cost_microunits,
        usage.reserved_cost_microunits,
        usage.used_output_bytes,
        usage.reserved_output_bytes,
        response.revision,
        response.model_attempts,
        response.tool_calls,
    ];
    if !valid_api_version(&response.api_version)
        || response.task_id != expected_task_id
        || response.task_id.parse::<TaskId>().is_err()
        || response.run_id.parse::<RunId>().is_err()
        || usage_values
            .iter()
            .any(|value| *value > MAXIMUM_JAVASCRIPT_SAFE_INTEGER)
        || response.model_attempts < usage.used_model_calls
        || response.tool_calls < usage.used_tool_calls
        || usage.used_retries > response.model_attempts
        || is_terminal_task_status(response.status)
            && (usage.reserved_model_calls != 0
                || usage.reserved_tool_calls != 0
                || usage.reserved_delegated_runs != 0
                || usage.reserved_input_tokens != 0
                || usage.reserved_output_tokens != 0
                || usage.reserved_cost_microunits != 0
                || usage.reserved_output_bytes != 0)
        || !valid_task_success_criteria(response)
    {
        return false;
    }
    let final_shape_valid = match (&response.final_response, &response.final_digest) {
        (None, None) => true,
        (Some(content), Some(digest)) => {
            !content.is_empty()
                && content.len() <= 64 * 1024
                && valid_sha256_digest(digest)
                && sha256_digest(content.as_bytes()) == *digest
        }
        _ => false,
    };
    final_shape_valid
        && response.validation.as_ref().is_none_or(|validation| {
            validation.validation_id.parse::<ValidationId>().is_ok()
                && validation.producer_run_id == response.run_id
                && validation.producer_run_id.parse::<RunId>().is_ok()
                && validation
                    .validator_run_id
                    .as_deref()
                    .is_none_or(|value| value.parse::<RunId>().is_ok())
                && validation
                    .context_manifest_id
                    .parse::<ContextManifestId>()
                    .is_ok()
                && validation.rubric.is_object()
                && validation.evidence.is_object()
                && valid_task_contract_text(&validation.policy_version)
                && validation.cursor.0 > 0
                && validation.cursor.0 <= MAXIMUM_JAVASCRIPT_SAFE_INTEGER
        })
}

fn valid_task_success_criteria(response: &TaskResponse) -> bool {
    let contract = &response.success_criteria;
    if !valid_task_contract_text(&contract.objective)
        || !valid_task_contract_text(&contract.policy_version)
        || !valid_sha256_digest(&contract.criteria_digest)
        || contract.criteria.len() > MAXIMUM_TASK_CRITERIA
        || contract.criteria.is_empty() == contract.no_objective_criteria_reason.is_none()
        || contract
            .no_objective_criteria_reason
            .as_deref()
            .is_some_and(|value| !valid_task_contract_text(value))
    {
        return false;
    }
    let mut identifiers = BTreeSet::new();
    contract.criteria.iter().all(|criterion| {
        valid_task_contract_text(&criterion.criterion_id)
            && valid_task_contract_text(&criterion.requirement)
            && identifiers.insert(criterion.criterion_id.as_str())
    })
}

fn valid_task_contract_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_TASK_CONTRACT_TEXT_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

const fn is_terminal_task_status(status: TaskStatus) -> bool {
    matches!(
        status,
        TaskStatus::Succeeded | TaskStatus::Failed | TaskStatus::Cancelled
    )
}

fn valid_extensions_response(response: &ExtensionsResponse) -> bool {
    if !valid_api_version(&response.api_version)
        || response.extensions.len() > MAXIMUM_DASHBOARD_EXTENSIONS
    {
        return false;
    }
    let mut identifiers = BTreeSet::new();
    response.extensions.iter().all(|extension| {
        identifiers.insert(extension.extension_id.as_str())
            && valid_extension_response(extension, None)
    })
}

fn valid_extension_response(
    response: &ExtensionResponse,
    expected_extension_id: Option<&str>,
) -> bool {
    let Ok(manifest) = serde_json::from_value::<ExtensionManifest>(response.manifest.clone())
    else {
        return false;
    };
    if !valid_api_version(&response.api_version)
        || expected_extension_id.is_some_and(|expected| response.extension_id != expected)
        || response.extension_id.parse::<ExtensionId>().is_err()
        || response.principal_id.parse::<PrincipalId>().is_err()
        || manifest.validate().is_err()
        || manifest.extension_id.to_string() != response.extension_id
        || manifest.name != response.name
        || manifest.publisher != response.publisher
        || manifest.version != response.version
        || !valid_sha256_digest(&response.manifest_digest)
        || response.manifest_history.is_empty()
        || response.manifest_history.len() > MAXIMUM_DASHBOARD_EXTENSION_HISTORY
        || response.last_healthy_at_ms.is_some_and(|value| value < 0)
        || response.last_failure_at_ms.is_some_and(|value| value < 0)
    {
        return false;
    }
    if !response.manifest_history.iter().all(|revision| {
        valid_sha256_digest(&revision.manifest_digest)
            && valid_extension_version(&revision.version)
            && revision.installed_at_ms >= 0
    }) {
        return false;
    }
    let Some(current_history) = response.manifest_history.last() else {
        return false;
    };
    if current_history.manifest_digest != response.manifest_digest
        || current_history.version != response.version
    {
        return false;
    }
    match (&response.status, &response.active_grant) {
        (ExtensionStatusResponse::Enabled, Some(grant)) => {
            response.last_healthy_at_ms.is_some()
                && grant.grant_id.parse::<ExtensionGrantId>().is_ok()
                && valid_sha256_digest(&grant.grant_digest)
                && grant.manifest_digest == response.manifest_digest
                && grant.policy_version == EXTENSION_POLICY_VERSION
                && grant.issued_at_ms >= 0
                && valid_extension_grant(&manifest, grant)
        }
        (status, grant) => *status != ExtensionStatusResponse::Enabled && grant.is_none(),
    }
}

fn valid_extension_grant(
    manifest: &ExtensionManifest,
    grant: &mealy_protocol::ExtensionGrantResponse,
) -> bool {
    if !valid_sorted_extension_identities(&grant.capability_ids, true)
        || !grant
            .capability_ids
            .iter()
            .all(|capability| manifest.capability(capability).is_some())
        || !grant
            .capability_ids
            .iter()
            .any(|capability| capability == &manifest.health_check.capability_id)
        || grant.mounts.len() > MAXIMUM_DASHBOARD_EXTENSION_GRANT_ITEMS
        || !valid_sorted_extension_identities(&grant.network_destinations, false)
        || !valid_sorted_extension_identities(&grant.secret_references, false)
        || !grant
            .network_destinations
            .iter()
            .all(|value| manifest.permissions.network_destinations.contains(value))
        || !grant
            .secret_references
            .iter()
            .all(|value| manifest.permissions.secret_references.contains(value))
        || grant.allow_process_spawn && !manifest.permissions.allow_process_spawn
    {
        return false;
    }
    let mut names = BTreeSet::new();
    let mut host_paths = BTreeSet::new();
    let mut sandbox_paths = BTreeSet::new();
    grant.mounts.iter().all(|mount| {
        names.insert(mount.name.as_str())
            && host_paths.insert(mount.host_path.as_str())
            && sandbox_paths.insert(mount.sandbox_path.as_str())
            && valid_extension_mount(manifest, mount)
    })
}

fn valid_extension_enable_request(
    request: &DashboardEnableExtensionRequest,
    current: &ExtensionResponse,
) -> bool {
    let Ok(manifest) = serde_json::from_value::<ExtensionManifest>(current.manifest.clone()) else {
        return false;
    };
    if !valid_sorted_extension_identities(&request.capability_ids, true)
        || !request
            .capability_ids
            .iter()
            .all(|capability| manifest.capability(capability).is_some())
        || !request
            .capability_ids
            .iter()
            .any(|capability| capability == &manifest.health_check.capability_id)
        || request.mounts.len() > MAXIMUM_DASHBOARD_EXTENSION_GRANT_ITEMS
        || !request
            .mounts
            .windows(2)
            .all(|pair| pair[0].name < pair[1].name)
        || !valid_sorted_extension_identities(&request.network_destinations, false)
        || !valid_sorted_extension_identities(&request.secret_references, false)
        || !request
            .network_destinations
            .iter()
            .all(|value| manifest.permissions.network_destinations.contains(value))
        || !request
            .secret_references
            .iter()
            .all(|value| manifest.permissions.secret_references.contains(value))
        || request.allow_process_spawn && !manifest.permissions.allow_process_spawn
    {
        return false;
    }
    let mut names = BTreeSet::new();
    let mut host_paths = BTreeSet::new();
    let mut sandbox_paths = BTreeSet::new();
    request.mounts.iter().all(|mount| {
        names.insert(mount.name.as_str())
            && host_paths.insert(mount.host_path.as_str())
            && sandbox_paths.insert(mount.sandbox_path.as_str())
            && valid_extension_mount(&manifest, mount)
    })
}

fn valid_extension_mount(
    manifest: &ExtensionManifest,
    mount: &mealy_protocol::ExtensionMountGrantCommand,
) -> bool {
    let Some(permission) = manifest
        .permissions
        .filesystem
        .iter()
        .find(|permission| permission.name == mount.name)
    else {
        return false;
    };
    let access_is_subset = match (permission.access, mount.access) {
        (
            ExtensionFilesystemAccess::ReadOnly | ExtensionFilesystemAccess::ReadWrite,
            ExtensionFilesystemAccessCommand::ReadOnly,
        )
        | (ExtensionFilesystemAccess::ReadWrite, ExtensionFilesystemAccessCommand::ReadWrite) => {
            true
        }
        (ExtensionFilesystemAccess::ReadOnly, ExtensionFilesystemAccessCommand::ReadWrite) => false,
    };
    access_is_subset
        && valid_dashboard_absolute_path(&mount.host_path)
        && valid_dashboard_absolute_path(&mount.sandbox_path)
}

fn valid_sorted_extension_identities(values: &[String], require_nonempty: bool) -> bool {
    (!require_nonempty || !values.is_empty())
        && values.len() <= MAXIMUM_DASHBOARD_EXTENSION_GRANT_ITEMS
        && values.iter().all(|value| valid_extension_identity(value))
        && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn valid_extension_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_DASHBOARD_EXTENSION_IDENTITY_BYTES
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

fn valid_extension_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
}

fn valid_dashboard_absolute_path(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= MAXIMUM_DASHBOARD_EXTENSION_PATH_BYTES
        && !value.contains('\\')
        && value
            .split('/')
            .skip(1)
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
        && !value.chars().any(char::is_control)
}

fn extension_grant_matches_request(
    extension: &ExtensionResponse,
    request: &DashboardEnableExtensionRequest,
) -> bool {
    extension.active_grant.as_ref().is_some_and(|grant| {
        grant.manifest_digest == extension.manifest_digest
            && grant.capability_ids == request.capability_ids
            && grant.mounts == request.mounts
            && grant.network_destinations == request.network_destinations
            && grant.secret_references == request.secret_references
            && grant.allow_process_spawn == request.allow_process_spawn
    })
}

fn same_extension_manifest_projection(left: &ExtensionResponse, right: &ExtensionResponse) -> bool {
    left.extension_id == right.extension_id
        && left.principal_id == right.principal_id
        && left.manifest_digest == right.manifest_digest
        && left.version == right.version
        && left.name == right.name
        && left.publisher == right.publisher
        && left.manifest == right.manifest
        && left.manifest_history == right.manifest_history
}

const fn memory_sensitivity_name(value: MemorySensitivityCommand) -> &'static str {
    match value {
        MemorySensitivityCommand::Public => "public",
        MemorySensitivityCommand::Internal => "internal",
        MemorySensitivityCommand::Private => "private",
        MemorySensitivityCommand::Restricted => "restricted",
    }
}

const fn memory_sensitivity_rank(value: MemorySensitivityCommand) -> u8 {
    match value {
        MemorySensitivityCommand::Public => 0,
        MemorySensitivityCommand::Internal => 1,
        MemorySensitivityCommand::Private => 2,
        MemorySensitivityCommand::Restricted => 3,
    }
}

fn invalid_dashboard_json() -> AxumResponse {
    dashboard_error(
        StatusCode::BAD_REQUEST,
        "dashboard_invalid_json",
        "The dashboard command body is missing, malformed, oversized, or has unknown fields.",
    )
}

fn invalid_dashboard_command() -> AxumResponse {
    dashboard_error(
        StatusCode::BAD_REQUEST,
        "dashboard_invalid_command",
        "The dashboard command failed its bounded local validation.",
    )
}

fn invalid_dashboard_query() -> AxumResponse {
    dashboard_error(
        StatusCode::BAD_REQUEST,
        "dashboard_invalid_query",
        "The dashboard query failed its bounded local validation.",
    )
}

fn invalid_dashboard_identifier() -> AxumResponse {
    dashboard_error(
        StatusCode::BAD_REQUEST,
        "dashboard_invalid_identifier",
        "The dashboard route identifier is invalid.",
    )
}

fn command_in_progress() -> AxumResponse {
    dashboard_error(
        StatusCode::TOO_MANY_REQUESTS,
        "dashboard_command_in_progress",
        "Another dashboard command is already in progress.",
    )
}

fn detail_in_progress() -> AxumResponse {
    dashboard_error(
        StatusCode::TOO_MANY_REQUESTS,
        "dashboard_detail_in_progress",
        "Another dashboard detail request is already in progress.",
    )
}

fn dashboard_state_conflict(operation: &str) -> AxumResponse {
    dashboard_error(
        StatusCode::CONFLICT,
        "dashboard_state_conflict",
        &format!(
            "The rendered state for the bounded {operation} operation is stale or conflicts with durable evidence."
        ),
    )
}

fn dashboard_protocol_error(operation: &str) -> AxumResponse {
    dashboard_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "dashboard_backend_protocol_error",
        &format!("The daemon returned an invalid {operation} response."),
    )
}

fn dashboard_backend_error(error: &CliError, operation: &str) -> AxumResponse {
    let status = match error {
        CliError::Server { status, .. } => match status.as_u16() {
            400 => StatusCode::BAD_REQUEST,
            404 => StatusCode::NOT_FOUND,
            409 => StatusCode::CONFLICT,
            410 => StatusCode::GONE,
            413 => StatusCode::PAYLOAD_TOO_LARGE,
            422 => StatusCode::UNPROCESSABLE_ENTITY,
            429 => StatusCode::TOO_MANY_REQUESTS,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        },
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };
    let code = if status == StatusCode::SERVICE_UNAVAILABLE {
        "dashboard_backend_unavailable"
    } else {
        "dashboard_command_rejected"
    };
    dashboard_error(
        status,
        code,
        &format!("The daemon could not complete the bounded {operation} operation."),
    )
}

fn dashboard_error(status: StatusCode, code: &str, message: &str) -> AxumResponse {
    (
        status,
        Json(serde_json::json!({
            "apiVersion": API_VERSION,
            "code": code,
            "message": message,
        })),
    )
        .into_response()
}

fn secure_response(mut response: AxumResponse, state: &DashboardState) -> AxumResponse {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        state.content_security_policy.clone(),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static(
            "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=()",
        ),
    );
    response
}

fn current_epoch_milliseconds() -> Result<u64, CliError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CliError::Protocol("system clock precedes the Unix epoch".to_owned()))?;
    u64::try_from(duration.as_millis())
        .map_err(|_| CliError::Protocol("system clock is outside the supported range".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::{
        DASHBOARD_TEMPLATE, DASHBOARD_TOKEN_PLACEHOLDER, DashboardCreateScheduleRequest,
        DashboardEnableExtensionRequest, DashboardState, MAXIMUM_JAVASCRIPT_SAFE_INTEGER,
        dashboard_memory_source_locator, schedule_matches_create_request, valid_admin_usage_report,
        valid_dashboard_mutation_origin, valid_dashboard_request_origin,
        valid_dashboard_schedule_create_request, valid_dashboard_token,
        valid_extension_enable_request, valid_extension_response, valid_memories_response,
        valid_memory_response, valid_memory_search_response, valid_reconciliation_evidence,
        valid_schedule_response, valid_schedule_runs_response, valid_task_response,
    };
    use axum::http::{HeaderMap, HeaderValue, header};
    use mealy_protocol::{
        AdminUsageBucketResponse, AdminUsageReportResponse, ExtensionFilesystemAccessCommand,
        ExtensionMountGrantCommand, ExtensionResponse, ExtensionStatusResponse, MemoriesResponse,
        MemoryResponse, MemorySearchResponse, MemorySensitivityCommand, MissedRunPolicyCommand,
        ScheduleOverlapPolicyCommand, ScheduleResponse, ScheduleRunsResponse, TaskResponse,
    };
    use reqwest::Client;
    use serde_json::json;
    use std::{path::PathBuf, sync::Arc};
    use tokio::sync::Semaphore;

    fn state() -> DashboardState {
        DashboardState {
            home: Arc::new(PathBuf::from("/tmp/not-used")),
            client: Client::new(),
            authority: Arc::from("127.0.0.1:41234"),
            origin: Arc::from("http://127.0.0.1:41234"),
            token: [7_u8; 32],
            html: Arc::from("fixture"),
            content_security_policy: HeaderValue::from_static("default-src 'none'"),
            snapshot_permit: Arc::new(Semaphore::new(1)),
            timeline_permit: Arc::new(Semaphore::new(1)),
            detail_permit: Arc::new(Semaphore::new(1)),
            command_permit: Arc::new(Semaphore::new(1)),
        }
    }

    #[test]
    fn usage_history_is_exact_integer_day_order_and_status_checked() {
        let from_ms = 86_400_100;
        let to_ms = 172_800_000;
        let mut report = AdminUsageReportResponse {
            api_version: "v1".to_owned(),
            from_ms,
            to_ms,
            buckets: vec![AdminUsageBucketResponse {
                bucket_start_ms: 86_400_000,
                bucket_end_ms: to_ms,
                completed_runs: 2,
                succeeded_runs: 1,
                failed_runs: 1,
                cancelled_runs: 0,
                used_model_calls: 3,
                used_tool_calls: 2,
                used_delegated_runs: 1,
                used_retries: 1,
                used_input_tokens: 100,
                used_output_tokens: 20,
                used_cost_microunits: 30,
                used_output_bytes: 40,
            }],
        };
        assert!(valid_admin_usage_report(&report, from_ms, to_ms));
        report.buckets[0].failed_runs = 2;
        assert!(!valid_admin_usage_report(&report, from_ms, to_ms));
        report.buckets[0].failed_runs = 1;
        report.buckets[0].used_cost_microunits = MAXIMUM_JAVASCRIPT_SAFE_INTEGER + 1;
        assert!(!valid_admin_usage_report(&report, from_ms, to_ms));
        report.buckets[0].used_cost_microunits = 30;
        report.buckets[0].bucket_start_ms += 1;
        assert!(!valid_admin_usage_report(&report, from_ms, to_ms));
    }

    #[test]
    fn reconciliation_evidence_is_a_nonempty_bounded_object() {
        assert!(valid_reconciliation_evidence(&serde_json::json!({
            "operatorObservation": "destination digest matched"
        })));
        assert!(!valid_reconciliation_evidence(&serde_json::json!({})));
        assert!(!valid_reconciliation_evidence(&serde_json::json!([
            "not an object"
        ])));
        assert!(!valid_reconciliation_evidence(&serde_json::json!({
            "oversized": "x".repeat(mealy_application::MAXIMUM_EFFECT_OUTCOME_DETAILS_BYTES)
        })));
    }

    #[test]
    fn schedule_evidence_is_identity_bound_revision_safe_and_shape_checked() {
        let schedule_id = "019f0000-0000-7000-8000-000000000031";
        let mut schedule: ScheduleResponse = serde_json::from_value(json!({
            "apiVersion": "v1",
            "scheduleId": schedule_id,
            "sessionId": "019f0000-0000-7000-8000-000000000032",
            "name": "daily evidence review",
            "prompt": "Review the latest durable evidence.",
            "cronExpression": "0 9 * * *",
            "timezone": "Pacific/Auckland",
            "missedRunPolicy": "latest",
            "overlapPolicy": "skip_if_running",
            "misfireGraceMs": 60_000,
            "allowApprovalRequiredAction": false,
            "status": "active",
            "nextDueAtMs": 1_900_000_000_000_i64,
            "revision": 0,
            "createdAtMs": 1_800_000_000_000_i64,
            "updatedAtMs": 1_800_000_000_000_i64
        }))
        .expect("schedule response");
        assert!(valid_schedule_response(&schedule, schedule_id));
        schedule.next_due_at_ms = None;
        assert!(!valid_schedule_response(&schedule, schedule_id));

        let runs: ScheduleRunsResponse = serde_json::from_value(json!({
            "apiVersion": "v1",
            "scheduleId": schedule_id,
            "runs": [{
                "scheduleRunId": "019f0000-0000-7000-8000-000000000033",
                "scheduleId": schedule_id,
                "scheduledForMs": 1_800_000_000_100_i64,
                "coalesced": false,
                "intent": "fire",
                "status": "admitted",
                "inboxEntryId": "019f0000-0000-7000-8000-000000000034",
                "reason": null,
                "createdAtMs": 1_800_000_000_101_i64,
                "completedAtMs": 1_800_000_000_102_i64
            }]
        }))
        .expect("schedule runs response");
        assert!(valid_schedule_runs_response(&runs, schedule_id, 1));
        assert!(!valid_schedule_runs_response(&runs, schedule_id, 0));
    }

    #[test]
    fn schedule_creation_is_uuidv7_keyed_definition_bound_and_action_gated() {
        let schedule_id = "019f0000-0000-7000-8000-000000000035";
        let mut request = DashboardCreateScheduleRequest {
            api_version: "v1".to_owned(),
            schedule_id: schedule_id.to_owned(),
            session_id: "019f0000-0000-7000-8000-000000000036".to_owned(),
            name: "daily evidence review".to_owned(),
            prompt: "Review the latest durable evidence.".to_owned(),
            cron_expression: "0 9 * * *".to_owned(),
            timezone: "Pacific/Auckland".to_owned(),
            missed_run_policy: MissedRunPolicyCommand::Latest,
            overlap_policy: ScheduleOverlapPolicyCommand::SkipIfRunning,
            misfire_grace_ms: 60_000,
            allow_approval_required_action: false,
        };
        assert!(valid_dashboard_schedule_create_request(&request));

        let mut schedule: ScheduleResponse = serde_json::from_value(json!({
            "apiVersion": "v1",
            "scheduleId": schedule_id,
            "sessionId": request.session_id,
            "name": request.name,
            "prompt": request.prompt,
            "cronExpression": request.cron_expression,
            "timezone": request.timezone,
            "missedRunPolicy": "latest",
            "overlapPolicy": "skip_if_running",
            "misfireGraceMs": 60_000,
            "allowApprovalRequiredAction": false,
            "status": "active",
            "nextDueAtMs": 1_900_000_000_000_i64,
            "revision": 0,
            "createdAtMs": 1_800_000_000_000_i64,
            "updatedAtMs": 1_800_000_000_000_i64
        }))
        .expect("schedule response");
        assert!(schedule_matches_create_request(&schedule, &request));

        request.schedule_id = "019f0000-0000-4000-8000-000000000035".to_owned();
        assert!(!valid_dashboard_schedule_create_request(&request));
        request.schedule_id = schedule_id.to_owned();
        request.prompt = "/run echo action".to_owned();
        assert!(!valid_dashboard_schedule_create_request(&request));
        request.prompt = "Review the latest durable evidence.".to_owned();
        schedule.name = "different definition".to_owned();
        assert!(!schedule_matches_create_request(&schedule, &request));
    }

    #[test]
    fn memory_evidence_binds_content_provenance_namespace_and_ranked_scope() {
        let memory_id = "019f0000-0000-7000-8000-000000000041";
        let revision_id = "019f0000-0000-7000-8000-000000000042";
        let workspace = "mealy://assistant/no-workspace";
        let content = "Prefer concise release summaries.";
        let digest = mealy_application::sha256_digest(content.as_bytes());
        let locator = dashboard_memory_source_locator("memory-unit-key");
        let mut memory: MemoryResponse = serde_json::from_value(json!({
            "apiVersion": "v1",
            "memoryId": memory_id,
            "principalId": "019f0000-0000-7000-8000-000000000043",
            "workspaceIdentity": workspace,
            "status": "proposed",
            "revision": 0,
            "category": "preference",
            "confidenceBasisPoints": 8_000,
            "sensitivity": "private",
            "retention": "standard",
            "createdAtMs": 1_800_000_000_000_i64,
            "lastVerifiedAtMs": 1_800_000_000_000_i64,
            "revisions": [{
                "revisionId": revision_id,
                "ordinal": 1,
                "status": "proposed",
                "content": content,
                "contentDigest": digest,
                "confidenceBasisPoints": 8_000,
                "sensitivity": "private",
                "retention": "standard",
                "supersedesRevisionId": null,
                "sources": [{"locator": locator, "digest": digest}],
                "createdAtMs": 1_800_000_000_000_i64,
                "lastVerifiedAtMs": 1_800_000_000_000_i64
            }]
        }))
        .expect("memory response");
        assert!(valid_memory_response(&memory, Some(memory_id), workspace));

        let listed = MemoriesResponse {
            api_version: "v1".to_owned(),
            memories: vec![memory.clone()],
        };
        assert!(valid_memories_response(&listed, workspace, false));
        let searched: MemorySearchResponse = serde_json::from_value(json!({
            "apiVersion": "v1",
            "hits": [{"memory": memory, "lexicalRank": 0.25}]
        }))
        .expect("memory search response");
        assert!(!valid_memory_search_response(
            &searched,
            workspace,
            MemorySensitivityCommand::Private,
            1
        ));

        memory = searched.hits[0].memory.clone();
        memory.status = mealy_protocol::MemoryStatusResponse::Active;
        memory.revision = 1;
        memory.revisions[0].status = mealy_protocol::MemoryStatusResponse::Active;
        assert!(valid_memory_response(&memory, Some(memory_id), workspace));
        let active_search = MemorySearchResponse {
            api_version: "v1".to_owned(),
            hits: vec![mealy_protocol::MemorySearchHitResponse {
                memory: memory.clone(),
                lexical_rank: -0.5,
            }],
        };
        assert!(valid_memory_search_response(
            &active_search,
            workspace,
            MemorySensitivityCommand::Private,
            1
        ));
        memory.revisions[0].content = Some("tampered".to_owned());
        assert!(!valid_memory_response(&memory, Some(memory_id), workspace));
    }

    #[test]
    fn extension_evidence_and_enable_grant_are_manifest_bounded() {
        let extension_id = "019f0000-0000-7000-8000-000000000051";
        let manifest_digest = "a".repeat(64);
        let mut extension: ExtensionResponse = serde_json::from_value(json!({
            "apiVersion": "v1",
            "extensionId": extension_id,
            "principalId": "019f0000-0000-7000-8000-000000000052",
            "status": "installed",
            "revision": 0,
            "manifestDigest": manifest_digest,
            "version": "1.0.0",
            "name": "dev.mealy.dashboard-fixture",
            "publisher": "dev.mealy",
            "manifest": {
                "schemaVersion": 1,
                "extensionId": extension_id,
                "name": "dev.mealy.dashboard-fixture",
                "publisher": "dev.mealy",
                "version": "1.0.0",
                "kinds": ["tool_service"],
                "compatibility": {"minimumHostApi": 1, "maximumHostApi": 1},
                "entryPoint": {"executable": "fixture", "executableDigest": "b".repeat(64), "runtimeFiles": []},
                "capabilities": [
                    {
                        "capabilityId": "health",
                        "kind": "health",
                        "effectClass": "read_only",
                        "riskClass": "low",
                        "inputSchema": {"properties": {}, "required": [], "additionalProperties": false, "maximumSerializedBytes": 1024},
                        "outputSchema": {"properties": {}, "required": [], "additionalProperties": false, "maximumSerializedBytes": 1024},
                        "timeoutMs": 1000,
                        "maximumOutputBytes": 1024
                    },
                    {
                        "capabilityId": "inspect",
                        "kind": "tool",
                        "effectClass": "read_only",
                        "riskClass": "low",
                        "inputSchema": {"properties": {}, "required": [], "additionalProperties": false, "maximumSerializedBytes": 1024},
                        "outputSchema": {"properties": {}, "required": [], "additionalProperties": false, "maximumSerializedBytes": 1024},
                        "timeoutMs": 1000,
                        "maximumOutputBytes": 1024
                    }
                ],
                "permissions": {
                    "filesystem": [{"name": "workspace", "access": "read_only"}],
                    "networkDestinations": ["api.example:443"],
                    "secretReferences": ["provider.primary"],
                    "allowProcessSpawn": true
                },
                "healthCheck": {"capabilityId": "health", "timeoutMs": 1000, "intervalMs": 5000},
                "migrations": [],
                "shutdown": {"mode": "terminate", "capabilityId": null, "gracePeriodMs": 1000}
            },
            "activeGrant": null,
            "manifestHistory": [{"manifestDigest": "a".repeat(64), "version": "1.0.0", "installedAtMs": 1_800_000_000_000_i64}],
            "lastHealthyAtMs": null,
            "lastFailureAtMs": null
        }))
        .expect("extension response");
        assert!(valid_extension_response(&extension, Some(extension_id)));

        let mut request = DashboardEnableExtensionRequest {
            api_version: "v1".to_owned(),
            expected_revision: 0,
            capability_ids: vec!["health".to_owned(), "inspect".to_owned()],
            mounts: vec![ExtensionMountGrantCommand {
                name: "workspace".to_owned(),
                access: ExtensionFilesystemAccessCommand::ReadOnly,
                host_path: "/srv/mealy-workspace".to_owned(),
                sandbox_path: "/workspace".to_owned(),
            }],
            network_destinations: vec!["api.example:443".to_owned()],
            secret_references: vec!["provider.primary".to_owned()],
            allow_process_spawn: false,
        };
        assert!(valid_extension_enable_request(&request, &extension));
        request.mounts[0].access = ExtensionFilesystemAccessCommand::ReadWrite;
        assert!(!valid_extension_enable_request(&request, &extension));
        request.mounts[0].access = ExtensionFilesystemAccessCommand::ReadOnly;

        extension.status = ExtensionStatusResponse::Enabled;
        extension.revision = 1;
        extension.last_healthy_at_ms = Some(1_800_000_000_100);
        extension.active_grant = Some(mealy_protocol::ExtensionGrantResponse {
            grant_id: "019f0000-0000-7000-8000-000000000053".to_owned(),
            grant_digest: "c".repeat(64),
            manifest_digest: "a".repeat(64),
            capability_ids: request.capability_ids,
            mounts: request.mounts,
            network_destinations: request.network_destinations,
            secret_references: request.secret_references,
            allow_process_spawn: request.allow_process_spawn,
            policy_version: mealy_application::EXTENSION_POLICY_VERSION.to_owned(),
            issued_at_ms: 1_800_000_000_100,
        });
        assert!(valid_extension_response(&extension, Some(extension_id)));
        extension
            .active_grant
            .as_mut()
            .expect("grant")
            .secret_references = vec!["undeclared.secret".to_owned()];
        assert!(!valid_extension_response(&extension, Some(extension_id)));
    }

    #[test]
    fn task_cost_evidence_is_exact_safe_integer_and_terminal_reservation_bounded() {
        let task_id = "019f0000-0000-7000-8000-000000000071";
        let content = "Completed with canonical evidence.";
        let mut task: TaskResponse = serde_json::from_value(json!({
            "apiVersion": "v1",
            "taskId": task_id,
            "runId": "019f0000-0000-7000-8000-000000000072",
            "status": "succeeded",
            "revision": 4,
            "finalResponse": content,
            "finalDigest": mealy_application::sha256_digest(content.as_bytes()),
            "usage": {
                "usedModelCalls": 2,
                "reservedModelCalls": 0,
                "usedToolCalls": 1,
                "reservedToolCalls": 0,
                "usedDelegatedRuns": 0,
                "reservedDelegatedRuns": 0,
                "usedRetries": 1,
                "usedInputTokens": 120,
                "reservedInputTokens": 0,
                "usedOutputTokens": 30,
                "reservedOutputTokens": 0,
                "usedCostMicrounits": 3456,
                "reservedCostMicrounits": 0,
                "usedOutputBytes": 512,
                "reservedOutputBytes": 0
            },
            "successCriteria": {
                "objective": "Return canonical evidence",
                "criteria": [{"criterionId": "response_digest", "requirement": "The response digest matches durable output"}],
                "noObjectiveCriteriaReason": null,
                "riskClass": "low",
                "policyVersion": "mealy.validation.phase4.v1",
                "criteriaDigest": "f".repeat(64)
            },
            "validation": null,
            "modelAttempts": 2,
            "toolCalls": 1
        }))
        .expect("task response");
        assert!(valid_task_response(&task, task_id));
        task.usage.reserved_cost_microunits = 1;
        assert!(!valid_task_response(&task, task_id));
        task.usage.reserved_cost_microunits = 0;
        task.usage.used_cost_microunits = 9_007_199_254_740_992;
        assert!(!valid_task_response(&task, task_id));
    }

    #[test]
    fn exact_loopback_host_origin_and_ephemeral_token_are_all_enforced() {
        let state = state();
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("127.0.0.1:41234"));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("http://127.0.0.1:41234"),
        );
        headers.insert(
            "x-mealy-dashboard",
            HeaderValue::from_static("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"),
        );
        assert!(valid_dashboard_request_origin(&state, &headers));
        assert!(valid_dashboard_mutation_origin(&state, &headers));
        assert!(valid_dashboard_token(&state, &headers));

        headers.remove(header::ORIGIN);
        assert!(valid_dashboard_request_origin(&state, &headers));
        assert!(!valid_dashboard_mutation_origin(&state, &headers));
        headers.insert(header::HOST, HeaderValue::from_static("attacker.example"));
        assert!(!valid_dashboard_request_origin(&state, &headers));
        headers.insert(header::HOST, HeaderValue::from_static("127.0.0.1:41234"));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("http://attacker.example"),
        );
        assert!(!valid_dashboard_request_origin(&state, &headers));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("http://127.0.0.1:41234"),
        );
        headers.insert(
            "x-mealy-dashboard",
            HeaderValue::from_static("CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg"),
        );
        assert!(!valid_dashboard_token(&state, &headers));
    }

    #[test]
    fn template_references_only_declared_elements_and_avoids_browser_persistence_sinks() {
        const PREFIX: &str = "getElementById(\"";
        let mut remainder = DASHBOARD_TEMPLATE;
        let mut references = 0_u32;
        while let Some((_, after_prefix)) = remainder.split_once(PREFIX) {
            let (identifier, after_identifier) = after_prefix
                .split_once("\")")
                .expect("literal getElementById reference");
            assert!(
                DASHBOARD_TEMPLATE.contains(&format!("id=\"{identifier}\"")),
                "dashboard script references missing element {identifier}"
            );
            references = references.saturating_add(1);
            remainder = after_identifier;
        }
        assert!(
            references >= 20,
            "dashboard element audit unexpectedly shrank"
        );
        assert_eq!(
            DASHBOARD_TEMPLATE
                .match_indices(DASHBOARD_TOKEN_PLACEHOLDER)
                .count(),
            1
        );
        for forbidden in [
            "innerHTML",
            "outerHTML",
            "document.cookie",
            "localStorage",
            "sessionStorage",
            "window.open",
            "eval(",
        ] {
            assert!(
                !DASHBOARD_TEMPLATE.contains(forbidden),
                "dashboard template contains forbidden browser sink {forbidden}"
            );
        }
    }
}
