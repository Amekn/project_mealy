//! Public-API, cold-restart proof for the Phase 3 approval-gated fixture write.

#![cfg(target_os = "linux")]

use mealy_application::sha256_digest;
use mealy_protocol::{
    API_VERSION, ApprovalDecisionCommand, ApprovalResolutionReceipt, ApprovalStatusResponse,
    CancelTaskRequest, CreateSessionRequest, CreateSessionResponse, DeliveryMode,
    EffectAttemptResponse, EffectAttemptStatusResponse, EffectOutcomeResponse,
    EffectReconciliationReceipt, EffectResponse, EffectStatusResponse, InputAdmissionResponse,
    LocalConnectionInfo, PendingApprovalsResponse, ReadinessResponse, ReconcileEffectRequest,
    ReconciliationOutcomeCommand, ResolveApprovalRequest, SubmitInputRequest,
    TaskCancellationReceipt, TaskReplayResponse, TaskResponse, TaskStatus, TimelineEvent,
    TimelinePageResponse,
};
use reqwest::{Client, StatusCode};
use rusqlite::{Connection, OptionalExtension};
use serde_json::json;
use std::{
    fs,
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};
use tempfile::TempDir;
use tokio::time::{Instant, sleep};

const READY_TIMEOUT: Duration = Duration::from_secs(15);
const COMPLETION_TIMEOUT: Duration = Duration::from_secs(30);
const WRITE_CONTENT: &str = "approved isolated write";

struct Daemon {
    child: Child,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn cancellation_revokes_pending_approval_and_unparks_without_dispatch() {
    if !Path::new("/usr/bin/bwrap").is_file() {
        return;
    }
    let home = TempDir::new().expect("temporary daemon home should be created");
    let workspace_file = home.path().join("fixture-workspace/cancelled.txt");
    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .expect("HTTP client should build");
    let _daemon = Daemon::spawn(home.path(), 0);
    let connection = wait_until_ready(&client, home.path()).await;
    let session: CreateSessionResponse = authorized_post(
        &client,
        &connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "phase-3-cancel-approval".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: format!(
                "fixture.write_file {}",
                json!({
                    "operation": "write_file",
                    "relativePath": "cancelled.txt",
                    "content": "must not survive cancellation",
                })
            ),
        },
    )
    .await;
    let (task_id, run_id) = wait_for_task_and_run(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let pending = wait_for_pending_approval(&client, &connection).await;
    let approval = pending
        .approvals
        .first()
        .expect("cancellation scenario should request approval");
    let effect_id = approval.effect_id.clone();
    let _: TaskCancellationReceipt = authorized_post(
        &client,
        &connection,
        &format!("/v1/tasks/{task_id}/cancel"),
        &CancelTaskRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "phase-3-cancel-command".to_owned(),
            reason: "owner cancelled while approval was pending".to_owned(),
        },
    )
    .await;
    let task = wait_until_task_cancelled(&client, &connection, &task_id).await;
    assert_eq!(task.status, TaskStatus::Cancelled);
    assert_eq!(task.model_attempts, 1);
    assert_eq!(task.tool_calls, 1);
    assert_eq!(task.usage.used_tool_calls, 1);
    assert_eq!(task.usage.reserved_tool_calls, 0);
    assert!(
        !workspace_file.exists(),
        "cancelled approval must not dispatch"
    );
    let effect: EffectResponse =
        authorized_get(&client, &connection, &format!("/v1/effects/{effect_id}")).await;
    assert_eq!(effect.status, EffectStatusResponse::Denied);
    assert_eq!(
        effect.approval.as_ref().map(|value| value.status),
        Some(ApprovalStatusResponse::Revoked)
    );
    let approvals: PendingApprovalsResponse =
        authorized_get(&client, &connection, "/v1/approvals").await;
    assert!(approvals.approvals.is_empty());
    assert_eq!(durable_effect_counts(home.path(), &run_id), (1, 1, 0, 0, 0));
    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    for event_type in [
        "approval.revoked",
        "effect.denied",
        "run.cancellation_ready",
        "task.cancelled",
    ] {
        assert_eq!(
            timeline
                .events
                .iter()
                .filter(|event| event.event_type == event_type)
                .count(),
            1,
            "expected one {event_type} event"
        );
    }
}

impl Daemon {
    fn spawn(home: &Path, agent_delay_ms: u64) -> Self {
        Self::spawn_configured(home, agent_delay_ms, 0, 0, 0, 300_000)
    }

    fn spawn_with_effect_delay(
        home: &Path,
        agent_delay_ms: u64,
        effect_outcome_delay_ms: u64,
    ) -> Self {
        Self::spawn_configured(home, agent_delay_ms, 0, effect_outcome_delay_ms, 0, 300_000)
    }

    fn spawn_with_dispatch_delay(home: &Path, effect_dispatch_delay_ms: u64) -> Self {
        Self::spawn_configured(home, 0, effect_dispatch_delay_ms, 0, 0, 300_000)
    }

    fn spawn_with_observation_delay(home: &Path, effect_observation_delay_ms: u64) -> Self {
        Self::spawn_configured(home, 0, 0, 0, effect_observation_delay_ms, 300_000)
    }

    fn spawn_with_approval_ttl(home: &Path, approval_ttl_ms: u64) -> Self {
        Self::spawn_configured(home, 0, 0, 0, 0, approval_ttl_ms)
    }

    fn spawn_configured(
        home: &Path,
        agent_delay_ms: u64,
        effect_dispatch_delay_ms: u64,
        effect_outcome_delay_ms: u64,
        effect_observation_delay_ms: u64,
        approval_ttl_ms: u64,
    ) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_mealyd"))
            .arg("--home")
            .arg(home)
            .arg("--promotion-delay-ms")
            .arg("0")
            .arg("--promotion-interval-ms")
            .arg("10")
            .arg("--outbox-delay-ms")
            .arg("0")
            .arg("--agent-delay-ms")
            .arg(agent_delay_ms.to_string())
            .arg("--effect-outcome-delay-ms")
            .arg(effect_outcome_delay_ms.to_string())
            .arg("--effect-dispatch-delay-ms")
            .arg(effect_dispatch_delay_ms.to_string())
            .arg("--effect-observation-delay-ms")
            .arg(effect_observation_delay_ms.to_string())
            .arg("--effect-approval-ttl-ms")
            .arg(approval_ttl_ms.to_string())
            .env("RUST_LOG", "error")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("mealyd process should start");
        Self { child }
    }

    fn hard_kill(&mut self) {
        self.child.kill().expect("mealyd should accept a hard kill");
        let status = self.child.wait().expect("killed mealyd should be reaped");
        assert!(
            !status.success(),
            "hard-killed mealyd must not exit cleanly"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn expired_approval_is_denied_and_resumed_without_owner_traffic() {
    if !Path::new("/usr/bin/bwrap").is_file() {
        return;
    }
    let home = TempDir::new().expect("temporary daemon home should be created");
    let workspace_file = home.path().join("fixture-workspace/expired.txt");
    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .expect("HTTP client should build");
    let _daemon = Daemon::spawn_with_approval_ttl(home.path(), 750);
    let connection = wait_until_ready(&client, home.path()).await;
    let session: CreateSessionResponse = authorized_post(
        &client,
        &connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "phase-3-expired-approval".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: format!(
                "fixture.write_file {}",
                json!({
                    "operation": "write_file",
                    "relativePath": "expired.txt",
                    "content": "must expire without mutation",
                })
            ),
        },
    )
    .await;
    let (task_id, run_id) = wait_for_task_and_run(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let pending = wait_for_pending_approval(&client, &connection).await;
    let approval = pending
        .approvals
        .first()
        .expect("expiry scenario should expose the pending subject");
    let effect_id = approval.effect_id.clone();
    let expires_at_ms = approval.subject.expires_at_ms;
    let task = wait_until_task_succeeds(&client, &connection, &task_id).await;
    assert_eq!(task.usage.used_tool_calls, 1);
    assert_eq!(task.usage.reserved_tool_calls, 0);
    assert!(
        !workspace_file.exists(),
        "expired approval must not dispatch"
    );
    let effect: EffectResponse =
        authorized_get(&client, &connection, &format!("/v1/effects/{effect_id}")).await;
    assert_eq!(effect.status, EffectStatusResponse::Denied);
    let expired = effect
        .approval
        .expect("denied effect should retain its approval evidence");
    assert_eq!(expired.status, ApprovalStatusResponse::Expired);
    assert_eq!(expired.decision, None);
    assert!(
        expired
            .resolved_at_ms
            .is_some_and(|value| value >= expires_at_ms)
    );
    let approvals: PendingApprovalsResponse =
        authorized_get(&client, &connection, "/v1/approvals").await;
    assert!(approvals.approvals.is_empty());
    assert_eq!(durable_effect_counts(home.path(), &run_id), (2, 1, 0, 0, 1));
    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    assert_eq!(
        timeline
            .events
            .iter()
            .filter(|event| event.event_type == "approval.expired")
            .count(),
        1
    );
    let replay: TaskReplayResponse =
        authorized_get(&client, &connection, &format!("/v1/tasks/{task_id}/replay")).await;
    assert!(replay.evidence_complete);
    assert_eq!((replay.live_provider_calls, replay.live_tool_calls), (0, 0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn denied_effect_never_dispatches_and_becomes_recorded_model_evidence() {
    if !Path::new("/usr/bin/bwrap").is_file() {
        return;
    }
    let home = TempDir::new().expect("temporary daemon home should be created");
    let workspace_file = home.path().join("fixture-workspace/denied.txt");
    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .expect("HTTP client should build");
    let _daemon = Daemon::spawn(home.path(), 0);
    let connection = wait_until_ready(&client, home.path()).await;
    let session: CreateSessionResponse = authorized_post(
        &client,
        &connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "phase-3-denied-write".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: format!(
                "fixture.write_file {}",
                json!({
                    "operation": "write_file",
                    "relativePath": "denied.txt",
                    "content": "must not be written",
                })
            ),
        },
    )
    .await;
    let (task_id, run_id) = wait_for_task_and_run(
        &client,
        &connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let pending = wait_for_pending_approval(&client, &connection).await;
    let approval = pending
        .approvals
        .first()
        .expect("denied scenario should request approval");
    let _: ApprovalResolutionReceipt = authorized_post(
        &client,
        &connection,
        &format!("/v1/approvals/{}/resolve", approval.approval_id),
        &ResolveApprovalRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "phase-3-deny-command".to_owned(),
            expected_subject_digest: approval.subject_digest.clone(),
            decision: ApprovalDecisionCommand::Deny,
        },
    )
    .await;
    let task = wait_until_task_succeeds(&client, &connection, &task_id).await;
    assert_eq!(task.model_attempts, 2);
    assert_eq!(task.tool_calls, 1);
    assert_eq!(task.usage.used_tool_calls, 1);
    assert_eq!(task.usage.reserved_tool_calls, 0);
    assert!(
        task.final_response
            .as_deref()
            .is_some_and(|response| response.contains("effect state denied"))
    );
    assert!(!workspace_file.exists(), "denied effect must never mutate");
    let effect: EffectResponse = authorized_get(
        &client,
        &connection,
        &format!("/v1/effects/{}", approval.effect_id),
    )
    .await;
    assert_eq!(effect.status, EffectStatusResponse::Denied);
    assert_eq!(
        effect.approval.as_ref().map(|value| value.status),
        Some(ApprovalStatusResponse::Denied)
    );
    assert_eq!(durable_effect_counts(home.path(), &run_id), (2, 1, 0, 0, 1));
    let replay: TaskReplayResponse =
        authorized_get(&client, &connection, &format!("/v1/tasks/{task_id}/replay")).await;
    assert!(replay.evidence_complete);
    assert_eq!(replay.tool_calls, 1);
    assert_eq!((replay.live_provider_calls, replay.live_tool_calls), (0, 0));
    assert!(!workspace_file.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn post_mutation_crash_parks_unknown_until_exact_reconciliation() {
    if !Path::new("/usr/bin/bwrap").is_file() {
        return;
    }
    let home = TempDir::new().expect("temporary daemon home should be created");
    let workspace_file = home.path().join("fixture-workspace/reconciled.txt");
    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .expect("HTTP client should build");
    let mut first_daemon = Daemon::spawn_with_effect_delay(home.path(), 0, 60_000);
    let first_connection = wait_until_ready(&client, home.path()).await;
    let session: CreateSessionResponse = authorized_post(
        &client,
        &first_connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &first_connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "phase-3-post-mutation-crash".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: format!(
                "fixture.write_file {}",
                json!({
                    "operation": "write_file",
                    "relativePath": "reconciled.txt",
                    "content": "mutation survived crash",
                })
            ),
        },
    )
    .await;
    let (task_id, run_id) = wait_for_task_and_run(
        &client,
        &first_connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let pending = wait_for_pending_approval(&client, &first_connection).await;
    let approval = pending
        .approvals
        .first()
        .expect("crash scenario should request approval");
    let effect_id = approval.effect_id.clone();
    let _: ApprovalResolutionReceipt = authorized_post(
        &client,
        &first_connection,
        &format!("/v1/approvals/{}/resolve", approval.approval_id),
        &ResolveApprovalRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "phase-3-crash-approval".to_owned(),
            expected_subject_digest: approval.subject_digest.clone(),
            decision: ApprovalDecisionCommand::Approve,
        },
    )
    .await;
    let attempt_id = wait_for_post_mutation_window(
        &client,
        &first_connection,
        home.path(),
        &workspace_file,
        &effect_id,
        &run_id,
    )
    .await;
    assert_eq!(
        fs::read_to_string(&workspace_file).expect("mutation should be durable before crash"),
        "mutation survived crash"
    );
    first_daemon.hard_kill();
    drop(first_daemon);
    remove_connection_descriptor(home.path());

    let _recovery_daemon = Daemon::spawn(home.path(), 0);
    let recovery_connection = wait_until_ready(&client, home.path()).await;
    let unknown = wait_until_effect_status(
        &client,
        &recovery_connection,
        &effect_id,
        EffectStatusResponse::OutcomeUnknown,
    )
    .await;
    let parked_task: TaskResponse = authorized_get(
        &client,
        &recovery_connection,
        &format!("/v1/tasks/{task_id}"),
    )
    .await;
    assert_eq!(parked_task.status, TaskStatus::Waiting);
    assert_eq!(parked_task.usage.reserved_tool_calls, 1);
    assert_eq!(parked_task.usage.used_tool_calls, 0);
    let interrupted: EffectAttemptResponse = authorized_get(
        &client,
        &recovery_connection,
        &format!("/v1/effect-attempts/{attempt_id}"),
    )
    .await;
    assert_eq!(
        interrupted.status,
        EffectAttemptStatusResponse::OutcomeUnknown
    );
    assert_eq!(interrupted.outcomes.len(), 1);
    assert_eq!(
        interrupted.outcomes[0].outcome,
        EffectOutcomeResponse::OutcomeUnknown
    );
    assert_eq!(durable_effect_counts(home.path(), &run_id), (1, 1, 1, 1, 0));
    assert_eq!(
        fs::read_to_string(&workspace_file).expect("recovery must not repeat the mutation"),
        "mutation survived crash"
    );

    let command = ReconcileEffectRequest {
        api_version: API_VERSION.to_owned(),
        idempotency_key: "phase-3-reconciliation-command".to_owned(),
        expected_effect_revision: unknown.revision,
        outcome: ReconciliationOutcomeCommand::Succeeded,
        evidence: json!({
            "basis": "verified exact fixture bytes after daemon restart",
            "contentDigest": sha256_digest(b"mutation survived crash"),
        }),
    };
    let receipt: EffectReconciliationReceipt = authorized_post(
        &client,
        &recovery_connection,
        &format!("/v1/effects/{effect_id}/attempts/{attempt_id}/reconcile"),
        &command,
    )
    .await;
    assert_eq!(receipt.effect_id, effect_id);
    assert_eq!(receipt.attempt_id, attempt_id);
    assert_eq!(receipt.outcome, ReconciliationOutcomeCommand::Succeeded);
    assert!(!receipt.duplicate);
    let duplicate: EffectReconciliationReceipt = authorized_post(
        &client,
        &recovery_connection,
        &format!("/v1/effects/{effect_id}/attempts/{attempt_id}/reconcile"),
        &command,
    )
    .await;
    let mut expected_duplicate = receipt.clone();
    expected_duplicate.duplicate = true;
    assert_eq!(duplicate, expected_duplicate);
    let conflict = ReconcileEffectRequest {
        outcome: ReconciliationOutcomeCommand::Failed,
        ..command.clone()
    };
    assert_post_status(
        &client,
        &recovery_connection,
        &format!("/v1/effects/{effect_id}/attempts/{attempt_id}/reconcile"),
        &conflict,
        StatusCode::CONFLICT,
    )
    .await;

    let task = wait_until_task_succeeds(&client, &recovery_connection, &task_id).await;
    assert_eq!(task.usage.used_tool_calls, 1);
    assert_eq!(task.usage.reserved_tool_calls, 0);
    let reconciled: EffectResponse = authorized_get(
        &client,
        &recovery_connection,
        &format!("/v1/effects/{effect_id}"),
    )
    .await;
    assert_eq!(reconciled.status, EffectStatusResponse::Succeeded);
    let reconciled_attempt: EffectAttemptResponse = authorized_get(
        &client,
        &recovery_connection,
        &format!("/v1/effect-attempts/{attempt_id}"),
    )
    .await;
    assert_eq!(
        reconciled_attempt.status,
        EffectAttemptStatusResponse::OutcomeUnknown
    );
    assert_eq!(reconciled_attempt.outcomes.len(), 2);
    assert_eq!(
        reconciled_attempt.outcomes[1].outcome,
        EffectOutcomeResponse::Succeeded
    );
    assert_eq!(durable_effect_counts(home.path(), &run_id), (2, 1, 1, 2, 1));
    let replay: TaskReplayResponse = authorized_get(
        &client,
        &recovery_connection,
        &format!("/v1/tasks/{task_id}/replay"),
    )
    .await;
    assert!(replay.evidence_complete);
    assert_eq!((replay.live_provider_calls, replay.live_tool_calls), (0, 0));
    assert_eq!(durable_effect_counts(home.path(), &run_id), (2, 1, 1, 2, 1));
    assert_eq!(
        fs::read_to_string(workspace_file).expect("replay must not repeat mutation"),
        "mutation survived crash"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn crash_after_effect_preparation_recovers_without_predispatch_mutation() {
    if !Path::new("/usr/bin/bwrap").is_file() {
        return;
    }
    let home = TempDir::new().expect("temporary daemon home should be created");
    let workspace_file = home.path().join("fixture-workspace/prepared-recovery.txt");
    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .expect("HTTP client should build");
    let mut first_daemon = Daemon::spawn_with_dispatch_delay(home.path(), 60_000);
    let first_connection = wait_until_ready(&client, home.path()).await;
    let session: CreateSessionResponse = authorized_post(
        &client,
        &first_connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &first_connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "phase-3-prepared-effect-crash".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: format!(
                "fixture.write_file {}",
                json!({
                    "operation": "write_file",
                    "relativePath": "prepared-recovery.txt",
                    "content": "dispatched only after recovery",
                })
            ),
        },
    )
    .await;
    let (task_id, run_id) = wait_for_task_and_run(
        &client,
        &first_connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let pending = wait_for_pending_approval(&client, &first_connection).await;
    let approval = pending
        .approvals
        .first()
        .expect("prepared crash should request approval");
    let effect_id = approval.effect_id.clone();
    let _: ApprovalResolutionReceipt = authorized_post(
        &client,
        &first_connection,
        &format!("/v1/approvals/{}/resolve", approval.approval_id),
        &ResolveApprovalRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "phase-3-prepared-crash-approval".to_owned(),
            expected_subject_digest: approval.subject_digest.clone(),
            decision: ApprovalDecisionCommand::Approve,
        },
    )
    .await;
    let first_attempt_id = wait_for_prepared_effect_window(
        &client,
        &first_connection,
        home.path(),
        &workspace_file,
        &effect_id,
        &run_id,
    )
    .await;
    assert!(!workspace_file.exists());
    first_daemon.hard_kill();
    drop(first_daemon);
    remove_connection_descriptor(home.path());

    let _recovery_daemon = Daemon::spawn(home.path(), 0);
    let recovery_connection = wait_until_ready(&client, home.path()).await;
    let task = wait_until_task_succeeds(&client, &recovery_connection, &task_id).await;
    assert_eq!(task.usage.used_tool_calls, 1);
    assert_eq!(task.usage.reserved_tool_calls, 0);
    assert_eq!(task.usage.used_retries, 0);
    assert_eq!(
        fs::read_to_string(&workspace_file).expect("recovered dispatch should create the file"),
        "dispatched only after recovery"
    );
    assert_eq!(durable_effect_counts(home.path(), &run_id), (2, 1, 2, 1, 1));
    let attempts = effect_attempt_states(home.path(), &effect_id);
    assert_eq!(attempts.len(), 2);
    assert_eq!(
        attempts[0],
        (first_attempt_id, "interrupted_undispatched".to_owned())
    );
    assert_eq!(attempts[1].1, "succeeded");
    let original: EffectAttemptResponse = authorized_get(
        &client,
        &recovery_connection,
        &format!("/v1/effect-attempts/{}", attempts[0].0),
    )
    .await;
    assert_eq!(
        original.status,
        EffectAttemptStatusResponse::InterruptedUndispatched
    );
    assert!(original.started_at_ms.is_none());
    assert!(original.outcomes.is_empty());
    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &recovery_connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    assert_eq!(
        timeline
            .events
            .iter()
            .filter(|event| event.event_type == "effect.attempt_prepared")
            .count(),
        2
    );
    assert_eq!(
        timeline
            .events
            .iter()
            .filter(|event| event.event_type == "effect.preparation_interrupted")
            .count(),
        1
    );
    let replay: TaskReplayResponse = authorized_get(
        &client,
        &recovery_connection,
        &format!("/v1/tasks/{task_id}/replay"),
    )
    .await;
    assert!(replay.evidence_complete);
    assert_eq!((replay.live_provider_calls, replay.live_tool_calls), (0, 0));
    assert_eq!(durable_effect_counts(home.path(), &run_id), (2, 1, 2, 1, 1));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn crash_after_effect_outcome_resumes_observation_without_redispatch() {
    if !Path::new("/usr/bin/bwrap").is_file() {
        return;
    }
    let home = TempDir::new().expect("temporary daemon home should be created");
    let workspace_file = home.path().join("fixture-workspace/terminal-recovery.txt");
    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .expect("HTTP client should build");
    let mut first_daemon = Daemon::spawn_with_observation_delay(home.path(), 60_000);
    let first_connection = wait_until_ready(&client, home.path()).await;
    let session: CreateSessionResponse = authorized_post(
        &client,
        &first_connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &first_connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "phase-3-terminal-effect-crash".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: format!(
                "fixture.write_file {}",
                json!({
                    "operation": "write_file",
                    "relativePath": "terminal-recovery.txt",
                    "content": "terminal evidence survives crash",
                })
            ),
        },
    )
    .await;
    let (task_id, run_id) = wait_for_task_and_run(
        &client,
        &first_connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let pending = wait_for_pending_approval(&client, &first_connection).await;
    let approval = pending
        .approvals
        .first()
        .expect("terminal crash should request approval");
    let effect_id = approval.effect_id.clone();
    let _: ApprovalResolutionReceipt = authorized_post(
        &client,
        &first_connection,
        &format!("/v1/approvals/{}/resolve", approval.approval_id),
        &ResolveApprovalRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "phase-3-terminal-crash-approval".to_owned(),
            expected_subject_digest: approval.subject_digest.clone(),
            decision: ApprovalDecisionCommand::Approve,
        },
    )
    .await;
    wait_for_terminal_preobservation_window(
        &client,
        &first_connection,
        home.path(),
        &workspace_file,
        &effect_id,
        &run_id,
    )
    .await;
    assert_eq!(
        fs::read_to_string(&workspace_file).expect("terminal mutation should exist"),
        "terminal evidence survives crash"
    );
    first_daemon.hard_kill();
    drop(first_daemon);
    remove_connection_descriptor(home.path());

    let _recovery_daemon = Daemon::spawn(home.path(), 0);
    let recovery_connection = wait_until_ready(&client, home.path()).await;
    let task = wait_until_task_succeeds(&client, &recovery_connection, &task_id).await;
    assert_eq!(task.usage.used_tool_calls, 1);
    assert_eq!(task.usage.reserved_tool_calls, 0);
    assert_eq!(durable_effect_counts(home.path(), &run_id), (2, 1, 1, 1, 1));
    assert_eq!(effect_attempt_states(home.path(), &effect_id).len(), 1);
    assert_eq!(
        fs::read_to_string(&workspace_file).expect("recovery must preserve one mutation"),
        "terminal evidence survives crash"
    );
    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &recovery_connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    assert_eq!(
        timeline
            .events
            .iter()
            .filter(|event| event.event_type == "effect.dispatched")
            .count(),
        1
    );
    assert_eq!(
        timeline
            .events
            .iter()
            .filter(|event| event.event_type == "effect.succeeded")
            .count(),
        1
    );
    assert_eq!(
        timeline
            .events
            .iter()
            .filter(|event| event.event_type == "message.tool.effect_observed")
            .count(),
        1
    );
    let replay: TaskReplayResponse = authorized_get(
        &client,
        &recovery_connection,
        &format!("/v1/tasks/{task_id}/replay"),
    )
    .await;
    assert!(replay.evidence_complete);
    assert_eq!((replay.live_provider_calls, replay.live_tool_calls), (0, 0));
    assert_eq!(durable_effect_counts(home.path(), &run_id), (2, 1, 1, 1, 1));
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn approved_effect_survives_restarts_executes_once_and_replays_without_dispatch() {
    if !Path::new("/usr/bin/bwrap").is_file() {
        return;
    }
    let home = TempDir::new().expect("temporary daemon home should be created");
    let workspace_file = home.path().join("fixture-workspace/result.txt");
    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .expect("HTTP client should build");

    let mut first_daemon = Daemon::spawn(home.path(), 0);
    let first_connection = wait_until_ready(&client, home.path()).await;
    let session: CreateSessionResponse = authorized_post(
        &client,
        &first_connection,
        "/v1/sessions",
        &CreateSessionRequest {
            api_version: API_VERSION.to_owned(),
        },
    )
    .await;
    let admission: InputAdmissionResponse = authorized_post(
        &client,
        &first_connection,
        &format!("/v1/sessions/{}/inputs", session.session_id),
        &SubmitInputRequest {
            api_version: API_VERSION.to_owned(),
            idempotency_key: "phase-3-approved-write".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: format!(
                "fixture.write_file {}",
                json!({
                    "operation": "write_file",
                    "relativePath": "result.txt",
                    "content": WRITE_CONTENT,
                })
            ),
        },
    )
    .await;
    let (task_id, run_id) = wait_for_task_and_run(
        &client,
        &first_connection,
        &session.session_id,
        admission.cursor.0,
    )
    .await;
    let pending = wait_for_pending_approval(&client, &first_connection).await;
    assert_eq!(pending.approvals.len(), 1);
    let approval = &pending.approvals[0];
    assert_eq!(approval.api_version, API_VERSION);
    assert_eq!(approval.subject.task_id, task_id);
    assert_eq!(approval.effect_id, approval.subject.effect_id);
    assert_eq!(approval.status, ApprovalStatusResponse::Pending);
    assert_eq!(approval.subject.tool_id, "fixture.write_file");
    assert_eq!(approval.subject.tool_version, "1");
    assert_eq!(approval.subject.capability_scope, "write:workspace");
    assert_eq!(approval.subject.target_resources.len(), 1);
    assert_eq!(approval.subject_digest.len(), 64);
    assert!(
        approval
            .subject_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    );
    assert!(!workspace_file.exists(), "approval must precede mutation");
    assert_eq!(durable_effect_counts(home.path(), &run_id), (1, 1, 0, 0, 0));
    assert_eq!(durable_tool_budget(home.path(), &run_id), (0, 1));

    let approval_id = approval.approval_id.clone();
    let effect_id = approval.effect_id.clone();
    let subject_digest = approval.subject_digest.clone();
    first_daemon.hard_kill();
    drop(first_daemon);
    remove_connection_descriptor(home.path());

    let mut approval_daemon = Daemon::spawn(home.path(), 60_000);
    let approval_connection = wait_until_ready(&client, home.path()).await;
    let restored = wait_for_pending_approval(&client, &approval_connection).await;
    assert_eq!(restored.approvals, pending.approvals);
    let command = ResolveApprovalRequest {
        api_version: API_VERSION.to_owned(),
        idempotency_key: "phase-3-approval-command".to_owned(),
        expected_subject_digest: subject_digest.clone(),
        decision: ApprovalDecisionCommand::Approve,
    };
    let receipt: ApprovalResolutionReceipt = authorized_post(
        &client,
        &approval_connection,
        &format!("/v1/approvals/{approval_id}/resolve"),
        &command,
    )
    .await;
    assert_eq!(receipt.approval_id, approval_id);
    assert_eq!(receipt.effect_id, effect_id);
    assert_eq!(receipt.status, ApprovalStatusResponse::Approved);
    assert_eq!(receipt.decision, ApprovalDecisionCommand::Approve);
    assert!(!receipt.duplicate);
    let duplicate: ApprovalResolutionReceipt = authorized_post(
        &client,
        &approval_connection,
        &format!("/v1/approvals/{approval_id}/resolve"),
        &command,
    )
    .await;
    let mut expected_duplicate = receipt.clone();
    expected_duplicate.duplicate = true;
    assert_eq!(duplicate, expected_duplicate);
    let conflicting = ResolveApprovalRequest {
        decision: ApprovalDecisionCommand::Deny,
        ..command.clone()
    };
    assert_post_status(
        &client,
        &approval_connection,
        &format!("/v1/approvals/{approval_id}/resolve"),
        &conflicting,
        StatusCode::CONFLICT,
    )
    .await;
    let authorized_effect: EffectResponse = authorized_get(
        &client,
        &approval_connection,
        &format!("/v1/effects/{effect_id}"),
    )
    .await;
    assert_eq!(authorized_effect.status, EffectStatusResponse::Authorized);
    assert!(
        !workspace_file.exists(),
        "authorization alone must not mutate"
    );
    assert_eq!(durable_effect_counts(home.path(), &run_id), (1, 1, 0, 0, 0));
    assert_eq!(durable_tool_budget(home.path(), &run_id), (0, 1));

    approval_daemon.hard_kill();
    drop(approval_daemon);
    remove_connection_descriptor(home.path());

    let _execution_daemon = Daemon::spawn(home.path(), 0);
    let execution_connection = wait_until_ready(&client, home.path()).await;
    let task = wait_until_task_succeeds(&client, &execution_connection, &task_id).await;
    assert_successful_task(&task, &task_id, &run_id);
    assert_eq!(
        fs::read_to_string(&workspace_file).expect("approved workspace file should exist"),
        WRITE_CONTENT
    );

    let effect: EffectResponse = authorized_get(
        &client,
        &execution_connection,
        &format!("/v1/effects/{effect_id}"),
    )
    .await;
    assert_successful_effect(&effect, &effect_id, &task_id, &run_id);
    let timeline: TimelinePageResponse = authorized_get(
        &client,
        &execution_connection,
        &format!("/v1/sessions/{}/timeline?limit=1000", session.session_id),
    )
    .await;
    assert_effect_timeline(&timeline.events, &effect_id);
    let attempt_id = timeline
        .events
        .iter()
        .find(|event| event.event_type == "effect.attempt_prepared")
        .and_then(|event| event.payload["attempt_id"].as_str())
        .expect("prepared effect event should expose its attempt ID");
    let attempt: EffectAttemptResponse = authorized_get(
        &client,
        &execution_connection,
        &format!("/v1/effect-attempts/{attempt_id}"),
    )
    .await;
    assert_eq!(attempt.effect_id, effect_id);
    assert_eq!(attempt.status, EffectAttemptStatusResponse::Succeeded);
    assert_eq!(attempt.ordinal, 1);
    assert_eq!(attempt.idempotency_key, effect.idempotency_key);
    assert!(attempt.started_at_ms.is_some());
    assert!(attempt.completed_at_ms.is_some());
    assert_eq!(attempt.outcomes.len(), 1);
    assert_eq!(attempt.outcomes[0].sequence, 0);
    assert_eq!(
        attempt.outcomes[0].outcome,
        EffectOutcomeResponse::Succeeded
    );
    assert_eq!(
        sha256_digest(attempt.outcomes[0].evidence.to_string().as_bytes()),
        attempt.outcomes[0].evidence_digest
    );

    let counts_before_replay = durable_effect_counts(home.path(), &run_id);
    assert_eq!(counts_before_replay, (2, 1, 1, 1, 1));
    assert_eq!(durable_tool_budget(home.path(), &run_id), (1, 0));
    let replay: TaskReplayResponse = authorized_get(
        &client,
        &execution_connection,
        &format!("/v1/tasks/{task_id}/replay"),
    )
    .await;
    assert!(replay.evidence_complete);
    assert_eq!(replay.final_response, task.final_response);
    assert_eq!(replay.final_digest, task.final_digest);
    assert_eq!(replay.model_attempts, 2);
    assert_eq!(replay.tool_calls, 1);
    assert_eq!(replay.live_provider_calls, 0);
    assert_eq!(replay.live_tool_calls, 0);
    assert_eq!(
        durable_effect_counts(home.path(), &run_id),
        counts_before_replay
    );
    assert_eq!(
        fs::read_to_string(workspace_file).expect("replay must preserve workspace bytes"),
        WRITE_CONTENT
    );
}

fn assert_successful_task(task: &TaskResponse, task_id: &str, run_id: &str) {
    assert_eq!(task.task_id, task_id);
    assert_eq!(task.run_id, run_id);
    assert_eq!(task.status, TaskStatus::Succeeded);
    assert_eq!(task.model_attempts, 2);
    assert_eq!(task.tool_calls, 1);
    assert_eq!(task.usage.used_model_calls, 2);
    assert_eq!(task.usage.reserved_model_calls, 0);
    assert_eq!(task.usage.used_tool_calls, 1);
    assert_eq!(task.usage.reserved_tool_calls, 0);
    assert_eq!(task.usage.used_retries, 0);
    assert!(task.usage.used_output_bytes > 0);
    assert_eq!(task.usage.reserved_output_bytes, 0);
    let response = task
        .final_response
        .as_deref()
        .expect("successful task should expose a response");
    assert!(response.starts_with("Fixture write reached durable effect state succeeded;"));
    assert_eq!(
        task.final_digest.as_deref(),
        Some(sha256_digest(response.as_bytes()).as_str())
    );
}

fn assert_successful_effect(effect: &EffectResponse, effect_id: &str, task_id: &str, run_id: &str) {
    assert_eq!(effect.api_version, API_VERSION);
    assert_eq!(effect.effect_id, effect_id);
    assert_eq!(effect.task_id, task_id);
    assert_eq!(effect.run_id, run_id);
    assert_eq!(effect.status, EffectStatusResponse::Succeeded);
    assert_eq!(effect.tool_id, "fixture.write_file");
    assert_eq!(effect.tool_version, "1");
    assert_eq!(effect.capability_scope, "write:workspace");
    assert_eq!(
        effect.normalized_arguments,
        json!({
            "content": WRITE_CONTENT,
            "operation": "write_file",
            "relativePath": "result.txt",
        })
    );
    assert_eq!(
        sha256_digest(effect.normalized_arguments.to_string().as_bytes()),
        effect.arguments_digest
    );
    assert!(effect.idempotency_key.is_some());
    assert_eq!(
        effect.approval.as_ref().map(|approval| approval.status),
        Some(ApprovalStatusResponse::Approved)
    );
}

fn assert_effect_timeline(events: &[TimelineEvent], effect_id: &str) {
    assert!(
        events
            .windows(2)
            .all(|pair| pair[0].cursor < pair[1].cursor)
    );
    for event_type in [
        "effect.proposed",
        "approval.requested",
        "approval.approved",
        "effect.authorized",
        "effect.attempt_prepared",
        "effect.dispatched",
        "effect.succeeded",
        "message.tool.effect_observed",
    ] {
        assert_eq!(
            events
                .iter()
                .filter(|event| event.event_type == event_type)
                .count(),
            1,
            "expected one {event_type} event"
        );
    }
    let ordered = [
        "effect.proposed",
        "approval.requested",
        "run.waiting_for_approval",
        "approval.approved",
        "effect.authorized",
        "run.effect_ready",
        "effect.attempt_prepared",
        "effect.dispatched",
        "effect.succeeded",
        "message.tool.effect_observed",
        "message.assistant.final",
        "run.succeeded",
        "task.succeeded",
    ];
    let mut next = 0;
    for event in events {
        if next < ordered.len() && event.event_type == ordered[next] {
            next += 1;
        }
    }
    assert_eq!(next, ordered.len(), "effect lifecycle order diverged");
    assert!(
        events
            .iter()
            .filter(|event| event.aggregate_id == effect_id)
            .count()
            >= 5
    );
}

async fn wait_until_ready(client: &Client, home: &Path) -> LocalConnectionInfo {
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        if let Ok(bytes) = fs::read(home.join("connection.json"))
            && let Ok(connection) = serde_json::from_slice::<LocalConnectionInfo>(&bytes)
            && let Ok(response) = client
                .get(format!("{}/health/ready", connection.base_url))
                .bearer_auth(&connection.bearer_token)
                .send()
                .await
            && response.status().is_success()
            && let Ok(readiness) = response.json::<ReadinessResponse>().await
            && readiness.ready
        {
            return connection;
        }
        assert!(Instant::now() < deadline, "mealyd did not become ready");
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_task_and_run(
    client: &Client,
    connection: &LocalConnectionInfo,
    session_id: &str,
    after: u64,
) -> (String, String) {
    let deadline = Instant::now() + COMPLETION_TIMEOUT;
    loop {
        let page: TimelinePageResponse = authorized_get(
            client,
            connection,
            &format!("/v1/sessions/{session_id}/timeline?after={after}&limit=100"),
        )
        .await;
        let task = page
            .events
            .iter()
            .find(|event| event.event_type == "task.created");
        let run = page
            .events
            .iter()
            .find(|event| event.event_type == "run.created");
        if let (Some(task), Some(run)) = (task, run) {
            return (task.aggregate_id.clone(), run.aggregate_id.clone());
        }
        assert!(Instant::now() < deadline, "input was not promoted");
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_pending_approval(
    client: &Client,
    connection: &LocalConnectionInfo,
) -> PendingApprovalsResponse {
    let deadline = Instant::now() + COMPLETION_TIMEOUT;
    loop {
        let pending: PendingApprovalsResponse =
            authorized_get(client, connection, "/v1/approvals").await;
        if !pending.approvals.is_empty() {
            return pending;
        }
        assert!(
            Instant::now() < deadline,
            "approval was not durably requested"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_post_mutation_window(
    client: &Client,
    connection: &LocalConnectionInfo,
    home: &Path,
    workspace_file: &Path,
    effect_id: &str,
    run_id: &str,
) -> String {
    let deadline = Instant::now() + COMPLETION_TIMEOUT;
    loop {
        let effect: EffectResponse =
            authorized_get(client, connection, &format!("/v1/effects/{effect_id}")).await;
        if workspace_file.exists()
            && effect.status == EffectStatusResponse::Dispatching
            && durable_effect_counts(home, run_id) == (1, 1, 1, 0, 0)
            && let Some(attempt_id) = running_effect_attempt(home, effect_id)
        {
            return attempt_id;
        }
        assert!(
            Instant::now() < deadline,
            "sandbox mutation did not enter the pre-outcome crash window"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_prepared_effect_window(
    client: &Client,
    connection: &LocalConnectionInfo,
    home: &Path,
    workspace_file: &Path,
    effect_id: &str,
    run_id: &str,
) -> String {
    let deadline = Instant::now() + COMPLETION_TIMEOUT;
    loop {
        let effect: EffectResponse =
            authorized_get(client, connection, &format!("/v1/effects/{effect_id}")).await;
        if !workspace_file.exists()
            && effect.status == EffectStatusResponse::Authorized
            && durable_effect_counts(home, run_id) == (1, 1, 1, 0, 0)
            && let Some(attempt_id) = prepared_effect_attempt(home, effect_id)
        {
            return attempt_id;
        }
        assert!(
            Instant::now() < deadline,
            "effect did not enter the prepared pre-dispatch crash window"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_terminal_preobservation_window(
    client: &Client,
    connection: &LocalConnectionInfo,
    home: &Path,
    workspace_file: &Path,
    effect_id: &str,
    run_id: &str,
) {
    let deadline = Instant::now() + COMPLETION_TIMEOUT;
    loop {
        let effect: EffectResponse =
            authorized_get(client, connection, &format!("/v1/effects/{effect_id}")).await;
        if workspace_file.exists()
            && effect.status == EffectStatusResponse::Succeeded
            && durable_effect_counts(home, run_id) == (1, 1, 1, 1, 0)
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "effect did not enter the terminal pre-observation crash window"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_until_effect_status(
    client: &Client,
    connection: &LocalConnectionInfo,
    effect_id: &str,
    expected: EffectStatusResponse,
) -> EffectResponse {
    let deadline = Instant::now() + COMPLETION_TIMEOUT;
    loop {
        let effect: EffectResponse =
            authorized_get(client, connection, &format!("/v1/effects/{effect_id}")).await;
        if effect.status == expected {
            return effect;
        }
        assert!(
            Instant::now() < deadline,
            "effect did not reach {expected:?}: {effect:?}"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_until_task_succeeds(
    client: &Client,
    connection: &LocalConnectionInfo,
    task_id: &str,
) -> TaskResponse {
    let deadline = Instant::now() + COMPLETION_TIMEOUT;
    loop {
        let task: TaskResponse =
            authorized_get(client, connection, &format!("/v1/tasks/{task_id}")).await;
        match task.status {
            TaskStatus::Succeeded => return task,
            TaskStatus::Failed | TaskStatus::Cancelled => {
                panic!("agent task reached an unexpected terminal state: {task:?}")
            }
            TaskStatus::Queued
            | TaskStatus::Running
            | TaskStatus::Waiting
            | TaskStatus::Paused
            | TaskStatus::Cancelling => {}
        }
        assert!(
            Instant::now() < deadline,
            "Phase 3 task did not succeed: {task:?}"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_until_task_cancelled(
    client: &Client,
    connection: &LocalConnectionInfo,
    task_id: &str,
) -> TaskResponse {
    let deadline = Instant::now() + COMPLETION_TIMEOUT;
    loop {
        let task: TaskResponse =
            authorized_get(client, connection, &format!("/v1/tasks/{task_id}")).await;
        match task.status {
            TaskStatus::Cancelled => return task,
            TaskStatus::Succeeded | TaskStatus::Failed => {
                panic!("cancelled task reached the wrong terminal state: {task:?}")
            }
            TaskStatus::Queued
            | TaskStatus::Running
            | TaskStatus::Waiting
            | TaskStatus::Paused
            | TaskStatus::Cancelling => {}
        }
        assert!(
            Instant::now() < deadline,
            "Phase 3 task did not cancel: {task:?}"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

async fn authorized_get<T: serde::de::DeserializeOwned>(
    client: &Client,
    connection: &LocalConnectionInfo,
    path: &str,
) -> T {
    let response = client
        .get(format!("{}{path}", connection.base_url))
        .bearer_auth(&connection.bearer_token)
        .send()
        .await
        .expect("authorized GET should reach mealyd");
    assert_eq!(response.status(), StatusCode::OK);
    response
        .json()
        .await
        .expect("response should be valid JSON")
}

async fn authorized_post<T: serde::de::DeserializeOwned>(
    client: &Client,
    connection: &LocalConnectionInfo,
    path: &str,
    body: &impl serde::Serialize,
) -> T {
    let response = client
        .post(format!("{}{path}", connection.base_url))
        .bearer_auth(&connection.bearer_token)
        .json(body)
        .send()
        .await
        .expect("authorized POST should reach mealyd");
    assert_eq!(response.status(), StatusCode::OK);
    response
        .json()
        .await
        .expect("response should be valid JSON")
}

async fn assert_post_status(
    client: &Client,
    connection: &LocalConnectionInfo,
    path: &str,
    body: &impl serde::Serialize,
    expected: StatusCode,
) {
    let response = client
        .post(format!("{}{path}", connection.base_url))
        .bearer_auth(&connection.bearer_token)
        .json(body)
        .send()
        .await
        .expect("authorized POST should reach mealyd");
    assert_eq!(response.status(), expected);
}

fn remove_connection_descriptor(home: &Path) {
    fs::remove_file(home.join("connection.json"))
        .expect("ephemeral endpoint descriptor should be removable");
}

fn open_database(home: &Path) -> Connection {
    let connection =
        Connection::open(home.join("mealy.sqlite3")).expect("durable Phase 3 database should open");
    connection
        .busy_timeout(Duration::from_secs(2))
        .expect("SQLite busy timeout should be configured");
    connection
}

fn durable_effect_counts(home: &Path, run_id: &str) -> (i64, i64, i64, i64, i64) {
    open_database(home)
        .query_row(
            "SELECT \
                (SELECT COUNT(*) FROM model_attempt WHERE run_id = ?1), \
                (SELECT COUNT(*) FROM agent_effect_invocation WHERE run_id = ?1), \
                (SELECT COUNT(*) FROM effect_attempt attempt \
                 JOIN effect ON effect.id = attempt.effect_id WHERE effect.run_id = ?1), \
                (SELECT COUNT(*) FROM effect_outcome outcome \
                 JOIN effect_attempt attempt ON attempt.attempt_id = outcome.attempt_id \
                 JOIN effect ON effect.id = attempt.effect_id WHERE effect.run_id = ?1), \
                (SELECT COUNT(*) FROM agent_effect_observation WHERE run_id = ?1)",
            [run_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .expect("durable effect counts should be queryable")
}

fn durable_tool_budget(home: &Path, run_id: &str) -> (i64, i64) {
    open_database(home)
        .query_row(
            "SELECT used_tool_calls, reserved_tool_calls FROM run_budget_usage WHERE run_id = ?1",
            [run_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("durable effect budget should be queryable")
}

fn running_effect_attempt(home: &Path, effect_id: &str) -> Option<String> {
    open_database(home)
        .query_row(
            "SELECT attempt_id FROM effect_attempt \
             WHERE effect_id = ?1 AND state = 'running' AND completed_at_ms IS NULL",
            [effect_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .expect("running effect attempt should be queryable")
}

fn prepared_effect_attempt(home: &Path, effect_id: &str) -> Option<String> {
    open_database(home)
        .query_row(
            "SELECT attempt_id FROM effect_attempt \
             WHERE effect_id = ?1 AND state = 'prepared' AND started_at_ms IS NULL",
            [effect_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .expect("prepared effect attempt should be queryable")
}

fn effect_attempt_states(home: &Path, effect_id: &str) -> Vec<(String, String)> {
    let connection = open_database(home);
    let mut statement = connection
        .prepare(
            "SELECT attempt_id, state FROM effect_attempt \
             WHERE effect_id = ?1 ORDER BY ordinal",
        )
        .expect("effect attempts should prepare for inspection");
    statement
        .query_map([effect_id], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("effect attempts should be queryable")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("effect attempt rows should decode")
}
