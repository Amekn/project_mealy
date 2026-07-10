# Threat Model

- Status: baseline for release-one design
Related requirements: `SEC-*`, `AUTH-*`, `TOOL-*`, `EXT-*`

## Security objective

Mealy should let one owner grant useful machine and service capabilities to an unreliable, externally influenced model without silently granting the model the full authority of the owner's OS account.

This is risk reduction, not a claim that arbitrary native code can be perfectly contained on every host. When a profile cannot be enforced, Mealy fails closed or labels an explicit full-trust downgrade.

## Assets

- owner files, repositories, devices, and local services;
- provider, channel, and service credentials;
- private conversations, context manifests, memories, and artifacts;
- task/effect/approval integrity;
- daemon configuration, policy, extension manifests, and audit history;
- availability, provider spend, and external service quotas;
- identity mappings between channel users and Mealy principals.

## Actors

| Actor | Default trust |
|---|---|
| Local owner principal | Trusted to administer Mealy; still subject to explicit high-risk confirmation UX |
| Model | Untrusted decision proposer |
| Remote/channel sender | Untrusted until platform verification and binding; then limited to principal grants |
| Retrieved web/file/message content | Untrusted data, even when it comes from an authorized principal |
| Built-in compiled adapter | Trusted code, reviewed with the daemon |
| Third-party extension | Untrusted native code confined to its host process and grants |
| Provider/service | External dependency; responses untrusted, credential scope limited |
| Sandbox worker | Disposable, lower-trust process |

## Trust boundaries

1. Channel/network to API: signature/token verification, replay protection, size/rate limits.
2. API to application: principal authorization and command validation.
3. Application to provider: privacy routing and secret broker.
4. Application to executor: capability token, sandbox profile, effect ID, fencing token.
5. Application to extension host: manifest grant and versioned RPC.
6. SQLite/artifacts to presentation: authorization and redaction.

Session IDs, task IDs, continuation tokens, and shared gateway secrets are never principal boundaries by themselves.

## Primary threats and controls

### Prompt injection causes a dangerous tool call

Controls: model is untrusted; typed tool schema; default-deny policy; exact approval binding; sandbox enforcement; no ambient credentials; risk-based validation. Prompt filtering may improve UX but is not credited as a boundary.

### Duplicate external effect after crash

Controls: durable intent-before-dispatch; stable idempotency key where supported; effect outcome state; stale-lease fencing; `outcome_unknown` reconciliation; no automatic non-idempotent retry.

### Forged approval through a chat message or client history

Controls: approval is an authenticated API command, not model-visible text; it binds the exact effect digest, principal, expiry, and policy version; argument changes invalidate it.

### Channel impersonation

Controls: verify raw request signatures in constant time; derive identity only from verified platform claims; bind platform identity to a principal; reject unbound or revoked identities.

### Session-ID authorization bypass

Controls: authorize every query/command using principal/resource grants. IDs are locators only.

### Malicious extension

Controls: data-only manifest inspection; digest/signature pin; out-of-process host; no inherited environment; capability-scoped RPC; resource limits; brokered secrets; kill/revoke without daemon restart.

### Sandbox escape or unsupported policy downgrade

Controls: platform backend tests; deny unsupported profiles; record backend and effective policy; make full-trust explicit; permit optional VM/container backends for stronger isolation.

### Secret disclosure in prompts or logs

Controls: opaque secret references; broker resolution at invocation; structured redaction before persistence/presentation; tests over provider payloads, journal, logs, artifacts, and child environments.

### Stale worker overwrites newer state

Controls: lease fencing token checked in every result transaction; monotonic revisions; expired workers cannot commit.

### Unbounded cost or resource exhaustion

Controls: durable queue caps, rate limits, concurrency limits, provider budgets, step/tool/output limits, bounded retries, sandbox memory/CPU/time, backpressure responses.

### Context or memory crosses principal/workspace boundary

Controls: namespace and authorization filters before relevance scoring; context manifest records inclusion; memory provenance and sensitivity; validator gets separately compiled context.

### Journal/artifact tampering

Controls: OS-user-only storage permissions; immutable journal API; content digests; foreign keys; backup/restore verification; optional encryption and future hash-chain checkpoints.

## Explicit non-boundaries

- prompt instructions;
- model self-critique;
- regex command classifiers;
- a human-readable warning without enforced policy;
- a tool allowlist when arbitrary unsandboxed shell remains available;
- a plugin manifest if plugin code still runs with daemon authority;
- a continuation token without principal authentication;
- output redaction as protection against a malicious process that already holds the secret.

## Release-one security gates

- No model-proposed mutation runs inside `mealyd`.
- Unsupported sandbox profiles fail closed in integration tests on each platform lane.
- Approval mutation/tampering tests cover every bound field.
- Duplicate delivery and stale lease tests prove no unauthorized transition.
- Provider payload and child environment tests prove secret minimization.
- Extension-host crash and malicious-request fixtures cannot stop or bypass the daemon.
- API binds loopback only and rejects missing credentials and disallowed Origins.

## Deferred risks

Multi-tenant adversarial hosting needs stronger tenant encryption, resource fairness, administrative separation, and probably separate OS identities or machines. This architecture preserves principal namespaces but does not claim release-one is a hostile multi-tenant boundary.
