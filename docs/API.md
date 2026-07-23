# Local API reference

Mealy exposes a versioned HTTP/JSON and Server-Sent Events API for owner-local integrations. The
supported release-one API version is `v1`. `mealyctl` is the preferred interactive client; direct
API clients are appropriate when they preserve the authentication, versioning, idempotency, and
cursor rules described here.

The transport DTOs are defined and documented in `crates/mealy-protocol/src/lib.rs`. Build the
complete Rust API documentation with:

```sh
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --all-features --no-deps
```

Open `target/doc/mealy_protocol/index.html` for request/response fields and
`target/doc/mealy_api/index.html` for the adapter contract. JSON field names are `camelCase` unless
a documented enum uses `snake_case`. Mutation bodies reject unsupported `apiVersion` values, and
most command DTOs reject unknown fields.

Before changing a public route, run
`scripts/validate-documentation.py --cli target/debug/mealyctl`. The protected documentation gate
compares this reference with every registered Axum method/path pair, so both an undocumented route
and a stale documented route fail CI.

## Connection and authentication

`mealyd` binds only to a loopback address. On startup it writes an owner-only connection descriptor
to `$MEALY_HOME/connection.json` (default `~/.mealy/connection.json`):

```json
{
  "apiVersion": "v1",
  "baseUrl": "http://127.0.0.1:37281",
  "bearerToken": "base64url-encoded-32-byte-token",
  "principalId": "opaque-principal-id",
  "channelBindingId": "opaque-binding-id"
}
```

Treat the entire file as a secret. Do not copy it into logs, command history, bug reports, URLs, or
browser storage. All routes except signed webhook delivery require exactly one header of the form
`Authorization: Bearer TOKEN`. An absent or malformed credential returns `401`; a valid credential
that does not own a resource returns a safe `403` response. Browser-origin requests are rejected
unless that exact origin is configured. Requests without an `Origin` header are permitted.

This example reads the protected readiness endpoint without placing the token itself in the shell
command line:

```sh
connection=${MEALY_HOME:-$HOME/.mealy}/connection.json
base_url=$(jq -er '.baseUrl' "$connection")
token=$(jq -er '.bearerToken' "$connection")
curl --fail-with-body --silent --show-error --config - <<EOF
url = "$base_url/health/ready"
header = "Authorization: Bearer $token"
EOF
unset token
```

The default maximum request body is 1 MiB. The daemon bounds concurrent commands and timeline
subscribers; excess work fails quickly with `429` instead of accumulating an unbounded queue.
Artifact-content responses are binary, use the committed media type, and set `Cache-Control:
no-store`, `X-Content-Type-Options: nosniff`, and attachment disposition.

## Common request flow

Create a session, submit an idempotent input, and read its durable timeline:

```sh
connection=${MEALY_HOME:-$HOME/.mealy}/connection.json
base_url=$(jq -er '.baseUrl' "$connection")
token=$(jq -er '.bearerToken' "$connection")

session=$(curl --fail-with-body --silent --show-error --config - <<EOF
url = "$base_url/v1/sessions"
request = "POST"
header = "Authorization: Bearer $token"
header = "Content-Type: application/json"
data = "{\"apiVersion\":\"v1\"}"
EOF
)
session_id=$(jq -er '.sessionId' <<EOF
$session
EOF
)

curl --fail-with-body --silent --show-error --config - <<EOF
url = "$base_url/v1/sessions/$session_id/inputs"
request = "POST"
header = "Authorization: Bearer $token"
header = "Content-Type: application/json"
data = "{\"apiVersion\":\"v1\",\"idempotencyKey\":\"example-001\",\"deliveryMode\":\"queue\",\"content\":\"Summarize my granted workspace.\"}"
EOF

curl --fail-with-body --silent --show-error --config - <<EOF
url = "$base_url/v1/sessions/$session_id/timeline?after=0&limit=100"
header = "Authorization: Bearer $token"
EOF
unset token
```

Retry a mutation only with the same idempotency key and identical semantic payload. Use a new key
for a new command. The delivery modes are `queue`, `steer_at_boundary`, and
`interrupt_then_queue`.

## Endpoints

Request and response names below refer to public types in `mealy_protocol`. `-` means there is no
JSON request body. Path IDs are opaque and must not be parsed for policy decisions.

### Health, sessions, tasks, and evidence

| Method | Path | Request or query | Response |
| --- | --- | --- | --- |
| `GET` | `/health/live` | - | `HealthResponse` |
| `GET` | `/health/ready` | - | `ReadinessResponse` |
| `GET` | `/v1/sessions` | `limit` (default 20, 1–100) | `SessionsResponse` |
| `POST` | `/v1/sessions` | `CreateSessionRequest` | `CreateSessionResponse` |
| `GET` | `/v1/sessions/search` | `query`, optional `limit` (default 20, 1–100) | `SessionSearchResponse` |
| `POST` | `/v1/sessions/{session_id}/inputs` | `SubmitInputRequest` | `InputAdmissionResponse` |
| `GET` | `/v1/sessions/{session_id}/status` | - | `SessionStatusResponse` |
| `GET` | `/v1/sessions/{session_id}/timeline` | optional `after`, optional `limit` | `TimelinePageResponse` |
| `GET` | `/v1/sessions/{session_id}/events` | optional `after`, optional `limit`; SSE | timeline events |
| `POST` | `/v1/sessions/{session_id}/compactions` | `CreateCompactionRequest` | `CompactionResponse` |
| `GET` | `/v1/compactions/{compaction_id}` | - | `CompactionResponse` |
| `GET` | `/v1/tasks/{task_id}` | - | `TaskResponse` |
| `POST` | `/v1/tasks/{task_id}/cancel` | `CancelTaskRequest` | `TaskCancellationReceipt` |
| `POST` | `/v1/tasks/{task_id}/pause` | `ControlTaskRequest` | `TaskControlReceipt` |
| `POST` | `/v1/tasks/{task_id}/resume` | `ControlTaskRequest` | `TaskControlReceipt` |
| `GET` | `/v1/tasks/{task_id}/replay` | - | `TaskReplayResponse` |
| `GET` | `/v1/delegations` | optional `limit` (default 20, 1–100) | `DelegationsResponse` |
| `GET` | `/v1/delegations/{delegation_id}` | - | `DelegationResponse` |
| `GET` | `/v1/context-manifests/{manifest_id}` | - | `ContextManifestEvidenceResponse` |
| `GET` | `/v1/artifacts/{artifact_id}` | - | `ArtifactMetadataResponse` |
| `GET` | `/v1/artifacts/{artifact_id}/content` | - | bounded artifact bytes |

### Schedules and governed memory

| Method | Path | Request or query | Response |
| --- | --- | --- | --- |
| `GET` | `/v1/schedules` | - | `SchedulesResponse` |
| `POST` | `/v1/schedules` | `CreateScheduleRequest` | `ScheduleResponse` |
| `GET` | `/v1/schedules/{schedule_id}` | - | `ScheduleResponse` |
| `POST` | `/v1/schedules/{schedule_id}/pause` | `ScheduleLifecycleRequest` | `ScheduleResponse` |
| `POST` | `/v1/schedules/{schedule_id}/resume` | `ScheduleLifecycleRequest` | `ScheduleResponse` |
| `POST` | `/v1/schedules/{schedule_id}/cancel` | `ScheduleLifecycleRequest` | `ScheduleResponse` |
| `GET` | `/v1/schedules/{schedule_id}/runs` | optional `limit` (default 100) | `ScheduleRunsResponse` |
| `GET` | `/v1/memories` | `workspaceIdentity`, optional `includeDeleted` | `MemoriesResponse` |
| `POST` | `/v1/memories` | `ProposeMemoryRequest` | `MemoryResponse` |
| `GET` | `/v1/memories/search` | `workspaceIdentity`, `query`, optional `maximumSensitivity`, optional `limit` | `MemorySearchResponse` |
| `GET` | `/v1/memories/{memory_id}` | `workspaceIdentity` | `MemoryResponse` |
| `POST` | `/v1/memories/{memory_id}/activate` | `PromoteMemoryRequest` | `MemoryResponse` |
| `POST` | `/v1/memories/{memory_id}/correct` | `CorrectMemoryRequest` | `MemoryResponse` |
| `POST` | `/v1/memories/{memory_id}/pin` | `SetMemoryPinRequest` | `MemoryResponse` |
| `POST` | `/v1/memories/{memory_id}/expire` | `MemoryLifecycleRequest` | `MemoryResponse` |
| `POST` | `/v1/memories/{memory_id}/reject` | `MemoryLifecycleRequest` | `MemoryResponse` |
| `POST` | `/v1/memories/{memory_id}/delete` | `MemoryLifecycleRequest` | `MemoryResponse` |
| `POST` | `/v1/memory-index/rebuild` | `RebuildMemoryIndexRequest` | `MemoryIndexRebuildResponse` |

### Approvals, effects, and extensions

| Method | Path | Request or query | Response |
| --- | --- | --- | --- |
| `GET` | `/v1/approvals` | - | `PendingApprovalsResponse` |
| `POST` | `/v1/approvals/{approval_id}/resolve` | `ResolveApprovalRequest` | `ApprovalResolutionReceipt` |
| `GET` | `/v1/effects/{effect_id}` | - | `EffectResponse` |
| `GET` | `/v1/effect-attempts/{attempt_id}` | - | `EffectAttemptResponse` |
| `POST` | `/v1/effects/{effect_id}/attempts/{attempt_id}/reconcile` | `ReconcileEffectRequest` | `EffectReconciliationReceipt` |
| `GET` | `/v1/extensions` | - | `ExtensionsResponse` |
| `POST` | `/v1/extensions` | `InstallExtensionRequest` | `ExtensionResponse` |
| `GET` | `/v1/extensions/{extension_id}` | - | `ExtensionResponse` |
| `POST` | `/v1/extensions/{extension_id}/stage` | `StageExtensionManifestRequest` | `ExtensionResponse` |
| `POST` | `/v1/extensions/{extension_id}/enable` | `EnableExtensionRequest` | `ExtensionResponse` |
| `POST` | `/v1/extensions/{extension_id}/disable` | `ExtensionLifecycleRequest` | `ExtensionResponse` |
| `POST` | `/v1/extensions/{extension_id}/revoke` | `ExtensionLifecycleRequest` | `ExtensionResponse` |
| `POST` | `/v1/extensions/{extension_id}/invoke` | `InvokeExtensionRequest` | `ExtensionInvocationResponse` |

### Channel administration

| Method | Path | Request or query | Response |
| --- | --- | --- | --- |
| `GET` | `/v1/channels/webhooks` | - | `WebhookChannelsResponse` |
| `POST` | `/v1/channels/webhooks` | `CreateWebhookChannelRequest` | `CreateWebhookChannelResponse` |
| `GET` | `/v1/channels/webhooks/{binding_id}` | - | `WebhookChannelResponse` |
| `POST` | `/v1/channels/webhooks/{binding_id}/revoke` | `RevokeWebhookChannelRequest` | `WebhookChannelResponse` |
| `GET` | `/v1/channels/telegram` | - | `TelegramChannelsResponse` |
| `POST` | `/v1/channels/telegram` | `CreateTelegramChannelRequest` | `TelegramChannelResponse` |
| `GET` | `/v1/channels/telegram/{binding_id}` | - | `TelegramChannelResponse` |
| `POST` | `/v1/channels/telegram/{binding_id}/revoke` | `RevokeTelegramChannelRequest` | `TelegramChannelResponse` |
| `GET` | `/v1/channels/discord` | - | `DiscordChannelsResponse` |
| `POST` | `/v1/channels/discord` | `CreateDiscordChannelRequest` | `DiscordChannelResponse` |
| `GET` | `/v1/channels/discord/{binding_id}` | - | `DiscordChannelResponse` |
| `POST` | `/v1/channels/discord/{binding_id}/revoke` | `RevokeDiscordChannelRequest` | `DiscordChannelResponse` |

The ingress-only `POST /v1/channels/webhooks/{binding_id}/deliveries` route does not accept the
local bearer. It requires exactly one `X-Mealy-Timestamp`, `X-Mealy-Nonce`, and
`X-Mealy-Signature` header. The signature is lower-case HMAC-SHA256 over the exact configured
framing and raw body. Use the binding-time client contract; do not reconstruct the framing from
this summary. Authentication and replay checks occur before JSON parsing.

### Administration

| Method | Path | Request or query | Response |
| --- | --- | --- | --- |
| `GET` | `/v1/admin/status` | - | `AdminStatusResponse` |
| `GET` | `/v1/admin/metrics` | - | `AdminMetricsResponse` |
| `GET` | `/v1/admin/usage` | `fromMs`, `toMs` | `AdminUsageReportResponse` |
| `GET` | `/v1/admin/doctor` | - | `DoctorResponse` |
| `POST` | `/v1/admin/drain` | `DrainDaemonRequest` | `DrainDaemonResponse` |
| `POST` | `/v1/admin/backups` | `CreateBackupRequest` | `BackupResponse` |
| `POST` | `/v1/admin/backup-verifications` | `VerifyBackupRequest` | `BackupVerificationResponse` |
| `POST` | `/v1/admin/artifact-gc` | `RunGarbageCollectionRequest` | `GarbageCollectionResponse` |
| `POST` | `/v1/admin/exports` | `CreateExportRequest` | `ExportResponse` |

`AdminStatusResponse` includes the effective provider/model and route health plus the effective
context limit, maximum output limit, provider-owned input-token overhead, and configured
input/output microunit prices. These secret-free capability fields let first-party clients explain
the active model boundary without reopening private configuration or guessing from a provider
catalog.

During safe mode or graceful drain, non-GET commands fail with retryable `503` except the bounded
maintenance commands for drain, backup, backup verification, and export.

## Timeline SSE and resumption

`GET /v1/sessions/{session_id}/events` returns `text/event-stream`. Supply the last durable cursor
as either `after=N` or `Last-Event-ID: N`; the query value takes precedence. Each event has:

- `id`: the decimal durable cursor;
- `event`: the stable timeline event type;
- `data`: one JSON `TimelineEvent`.

The server sends a keep-alive comment every 15 seconds. Persist a cursor only after the event has
been processed. Reconnect with that cursor; consumers must tolerate exact redelivery. A cursor
ahead of canonical state or older than retained history returns a conflict (`timeline_cursor_ahead`
or `timeline_gap`). SSE error events carry the same `ApiErrorResponse` JSON envelope and terminate
the stream.

## Errors and retry policy

JSON errors have this stable shape:

```json
{
  "apiVersion": "v1",
  "code": "invalid_request",
  "message": "safe bounded detail",
  "retryable": false
}
```

| HTTP | Typical code | Meaning |
| --- | --- | --- |
| `400` | `invalid_request` | Malformed query/body, unsupported version, or failed command validation |
| `401` | `invalid_credential` | Local bearer missing or invalid |
| `403` | `origin_forbidden`, `unauthorized` | Origin denied or authenticated identity lacks ownership |
| `404` | `not_found` | Route or owned resource not found |
| `405` | `method_not_allowed` | Wrong HTTP method |
| `409` | `conflict`, `timeline_gap`, `timeline_cursor_ahead` | Revision, state, or cursor conflict |
| `413` | `payload_too_large` | Request exceeds the configured body limit |
| `429` | `busy` | Bounded concurrency is exhausted; retryable |
| `503` | `unavailable`, `admission_closed` | Dependency unavailable, safe mode, or drain; retryable where marked |
| `500` | `internal` | Safe internal failure |

Use the response's `retryable` value, bounded exponential backoff, and a retry ceiling. Never
blindly retry a mutation with a new idempotency key. Do not infer authorization state from the
difference between `403` and `404`.

## Compatibility contract

Clients must send `apiVersion: "v1"` on mutation DTOs and require `apiVersion == "v1"` in JSON
responses. Additive response fields may appear within `v1`; tolerant readers should ignore fields
they do not use. Field removal, semantic reinterpretation, or incompatible enum changes require a
new API version. The authoritative compatibility tests live in `mealy-api`, `mealy-protocol`, and
the real-daemon public-API scenario suites described in [TESTING.md](TESTING.md).
