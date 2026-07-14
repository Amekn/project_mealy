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
- daemon configuration, policy, skill/extension manifests, and audit history;
- availability, provider spend, and external service quotas;
- identity mappings between channel users and Mealy principals.

## Actors

| Actor | Default trust |
|---|---|
| Local owner principal | Trusted to administer Mealy; still subject to explicit high-risk confirmation UX |
| Model | Untrusted decision proposer |
| Remote/channel sender | Untrusted until platform verification and binding; then limited to principal grants |
| Retrieved web/file/message content | Untrusted data, even when it comes from an authorized principal |
| Installed skill | Owner-reviewed instructions/passive data; never executable or authority-bearing by itself |
| Delegated child model run | Untrusted bounded computation with explicit isolated context and an intersected read-only grant |
| Built-in compiled adapter | Trusted code, reviewed with the daemon |
| Third-party extension | Untrusted native code confined to its host process and grants |
| Local MCP stdio server | Untrusted owner-selected native code confined to a fresh read-only sandbox and exact schema/tool-set grant |
| Chrome Headless Shell and rendered page | Untrusted browser/runtime content confined to a fresh agent-only profile, private network namespace, and exact GET/HEAD destination grant |
| Provider/service | External dependency; responses untrusted, credential scope limited |
| Sandbox worker | Disposable, lower-trust process |

## Trust boundaries

1. Channel/network to API: signature/token verification, replay protection, size/rate limits.
2. API to application: principal authorization and command validation.
3. Application to provider: privacy routing and secret broker.
4. Application to executor: capability token, sandbox profile, effect ID, fencing token.
5. Application to extension host: manifest grant and versioned RPC.
6. Skill package to context/resource tool: exact inventory/digest verification, separate activation, and bounded reads.
7. MCP server to tool evidence: executable/full-toolset/schema pinning, exact protocol lifecycle,
   fresh no-network process isolation, bounded arguments/results, cancellation, and cited replay.
8. Parent run to delegated child: explicit work package, read-only capability intersection,
   separate budget, depth zero, durable result fence, and cancellation propagation.
9. Browser/page to evidence: complete runtime pin, private profile/network namespace, scoped
   Unix-socket proxy, GET/HEAD plus upgrade denial, CDP filtering, output normalization, and cleanup.
10. SQLite/artifacts to presentation: authorization and redaction.

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

Telegram pairing accepts only a random expiring command from a non-bot sender whose ID and private
chat are exact. Discord pairing independently verifies the bot token, API v10 current-user object,
type-1 DM, and sole non-bot recipient, then accepts the random command only from that recipient and
channel. Runtime Discord messages must repeat the exact channel/author claims, default message
type, and non-webhook/non-bot classification. Platform IDs are canonical decimal strings, not
authorization by possession. Setup and runtime cursors fence old traffic; reservations make crash
replay idempotent; revocation removes future target discovery while retaining evidence.

### Channel backlog, rate, mention, and duplicate-message abuse

Controls: bounded response bytes and record counts; Telegram long-poll limits; Discord full-page
backward traversal to a durable floor; no cursor advance on malformed, oversized, or over-ceiling
history; shared parsing of platform `Retry-After`; long cooldown after invalid Discord authority;
durable queue backpressure; output truncation; Discord `allowed_mentions.parse=[]` and embed
suppression; stable outbox-derived nonce with `enforce_nonce`; exact channel/bot/nonce/message
acknowledgement; and terminal parking when remote acceptance is ambiguous. Attachments in the
Discord DM profile are ignored rather than fetched. Token bytes are header-only and the production
base is the exact official API v10 endpoint, preventing credential exfiltration through an
operator-supplied alternate HTTPS origin.

### Session-ID authorization bypass

Controls: authorize every query/command using principal/resource grants. IDs are locators only.

### Malicious extension

Controls: data-only manifest inspection; digest/signature pin; out-of-process host; no inherited environment; capability-scoped RPC; resource limits; brokered secrets; kill/revoke without daemon restart.

### Ambient executable or loader environment replaces a trusted sandbox helper

Controls: Bubblewrap and dynamic-linker inspection use exact absolute system paths whose complete
file and directory chains must remain root-controlled. Dynamic runtime discovery invokes only
`/usr/bin/ldd`, clears the inherited environment, sets a deterministic locale, and places `--`
before the already-canonical worker or configured root-controlled command. The daemon does not
search the owner's `PATH` or pass `LD_*` state into this trusted setup step. Missing or unsafe
helpers make the affected tool profile unavailable; they never select an alternate executable or
fall back to unsandboxed dispatch.

### Workspace, extension mount, or local attachment exposes daemon secrets

Controls: the canonical Mealy home and every candidate host root/file are resolved before
authority is published or content is framed. A workspace or extension mount is rejected when it
equals the home, is below it, contains it, is redirected, or is unavailable; daemon startup and
every extension enable/invocation repeat the relevant check. Local text attachments bind the
opened file identity to its canonical path and reject any file below the home before API
admission. Secret access remains a separate broker/reference boundary. The generated Linux unit
derives its write exceptions only from the same validated writable workspace set.

### Service namespace hides or discards the configured state

Controls: Linux service generation holds the stopped-home lock, canonicalizes every path, and
rejects a home or workspace beneath host `/tmp` or `/var/tmp`, which the outer Bubblewrap namespace
replaces. It also rejects a home on `tmpfs` or `ramfs`, applies `UMask=0077`, and gives the outer
Bubblewrap process writable binds only for the home plus current writable workspaces. A custom unit
path must retain the exact `mealy.service` name and is linked explicitly. The intentional status-2
forced-drain exit is restart-inhibited, preventing supervision from reopening admission after an
operator drain. The outer namespace supplies a minimal device tree, private process and temporary
filesystems, read-only host view, capability drop, and separate user/PID/UTS/IPC namespaces while
sharing the network needed by configured providers and channels. Rootless-compatible systemd
socket-family, syscall-ABI, realtime, resource, and `NoNewPrivileges` controls remain in force.
Per-request nested Bubblewrap mounts retain the narrower governed tool boundary.

### Malicious or changed skill package widens authority

Controls: complete no-symlink inventory and exact manifest/asset digest/size checks without code
execution; immutable private publication; install/update disabled; manifest-digest-fenced activation;
startup re-verification; bounded lower-precedence instruction context; passive resources loaded only
through a bounded cited read tool. Required tool contracts are inspection references and never add
tools, workspaces, network, processes, secrets, extensions, or delegation to the capability ceiling.

### Malicious or changed MCP server gains ambient authority

Controls: inspection and activation require an exact canonical native ELF and explicit selected
tool names; installation publishes owner-private content-addressed bytes. The negotiated protocol,
complete paginated advertised tool set, each selected full definition, self-contained input/output
schema, direct non-secret arguments, timeout, and output ceiling are pinned. Startup and every call
re-hash and re-discover before dispatch, so missing, extra, or changed tools remove authority.
Annotations are retained as untrusted evidence and never authorize effects. Each discovery/call
uses a fresh Bubblewrap namespace with an empty environment, no network, Mealy home, workspace,
secrets, shell, `PATH`, persistent writable mount, or child-process budget; only the exact server,
launcher, runtime libraries, private `/proc`/`dev`, and ephemeral `/tmp` exist. Hard protocol,
CPU, memory, file, descriptor, process, output, and wall-clock bounds contain failure; cancellation
is signalled and followed by termination. Output is untrusted, schema-checked when declared, cited,
persisted, and replayed without execution. The server still sees arguments deliberately sent to
it, and the host kernel remains the native-code isolation boundary.

### Parent model delegates hidden context or excess authority

Controls: `agent.delegate` accepts only bounded objective/instructions/criteria and optional object
context; the child receives no implicit parent conversation, memory, approvals, or effect history.
Effective child tools are a fresh read-only intersection of the parent's immutable ceiling and
current runtime policy; mutation/process tools, writable roots, executable identities, and further
delegation are removed. Child limits are separately enforced, launch and parent parking are atomic,
terminal results are fencing-token bound, and parent cancellation propagates before either budget
settles. Owner list/status and root/child recorded replay make the boundary independently auditable.

### Malicious page turns a read-only browser into ambient network or personal-profile authority

Controls: Mealy accepts only a completely inventoried, content-addressed Chrome Headless Shell
bundle whose executable banner and CDP product/protocol identity are pinned. It never launches the
owner's normal browser or profile. Every call uses a new private writable profile inside a fresh
Bubblewrap user/PID/mount/network namespace with an empty environment and no home, workspace,
secret, host browser, or host CDP mount. Chrome can reach only a loopback relay whose Unix socket
terminates at a host policy proxy; the proxy independently applies the persisted web destination
claims, rejects private/mixed DNS except an exact HTTP loopback origin, pins peer addresses, admits
only GET/HEAD or an authorized HTTPS tunnel, and bounds headers, aggregate bytes, time, 32
concurrent connections, and 256 accepted connections per call at both proxy layers. Completed
connection threads are joined during the call rather than retained until shutdown, and a lease
releases the concurrency slot even if a handler unwinds. It intersects those claims with the
initial URL's exact origin for the whole call; a page
cannot pivot through a configured cross-origin redirect, subresource, or accessible link. Fetch
interception rejects every non-GET/HEAD request and authentication. Ambient downloads are denied;
one exact accessible same-origin link may instead use CDP `allowAndName` in a per-call ephemeral
directory. Mealy validates the GUID, caps progress/total/file bytes at 512 KiB, opens with
`NOFOLLOW`, returns digest/base64 evidence, and destroys the profile without mounting an owner
path. Progress counters must be non-negative integral JSON numbers within exact IEEE-754 range;
fractions, negatives, inexact values, and over-limit bytes fail closed. WebSocket, WebTransport,
QUIC, direct sockets, service workers, beacon/native form
submission, and non-read Fetch/XHR are blocked or make the call fail. Exact text filling accepts
only native non-password text controls and uses value setters captured before page code without
dispatching page events. Optional GET submission is reconstructed in Rust from only the selected
named control after same-origin/method/target validation, so hidden/sibling fields and page submit
handlers cannot widen it. HTTPS tunnel contents cannot be classified by
the host proxy alone, so the independent CDP/network/API blocks are part of the browser boundary;
future effectful interaction must not reuse the read-only classification.

Only bounded accessibility text and role/name/occurrence records, final URL/title, exact fill
target/value byte count/digest, optional submitted GET URL, one optional bounded attachment's
URL/size/digest/base64, and an optional validated PNG enter
durable evidence. A submitted URL necessarily contains the selected encoded value; hidden/sibling
control values do not. Raw DOM, CDP, cookies, profile files, and browser stderr do not enter
evidence. The process/profile/socket are destroyed after success, failure, cancellation, or
deadline; recorded replay launches neither Chrome nor network. CPU/process/file/descriptor/output
limits apply per call. Because V8 requires a large virtual address reservation, the supported
systemd deployment applies a physical-memory/task/swap cgroup ceiling to `mealyd` and all children;
a direct launch without an equivalent cgroup is not the fully contained browser deployment. The
native browser and host kernel remain trusted-computing-base risks, so pinned-browser security
updates and the x86_64 conformance job are release requirements.

### Sandbox escape or unsupported policy downgrade

Controls: platform backend tests; deny unsupported profiles; record backend and effective policy; make full-trust explicit; permit optional VM/container backends for stronger isolation.

### Browser page or DNS rebinding steals local operational authority

Controls: the optional operations dashboard is a foreground `mealyctl` adapter on a random numeric
`127.0.0.1` port, never the daemon API itself. It embeds a separate 256-bit lifetime capability in
a no-store page; the daemon bearer is retained only by the CLI process and is never returned in
HTML, JSON, URLs, logs, or browser storage. Every request requires the exact numeric Host, API
access additionally uses constant-time capability validation, and every mutation requires the
exact loopback Origin rather than accepting an Origin-less request. A restrictive CSP,
`frame-ancestors 'none'`, same-origin resource/opener policies, no CORS allowance, 64 KiB request
bodies, canonical UUID route parsing, bounded timelines/evidence, and separate one-at-a-time
snapshot, timeline, detail, and command permits limit compromise. Every daemon body is streamed
under an 8 MiB ceiling before decode. The adapter exposes only a
hard-coded snapshot, session create/input, timeline, exact approval-resolution, cooperative
task-cancellation, exact bounded 30-day terminal usage and per-task usage/cost inspection, effect/attempt inspection,
unknown-effect reconciliation, and exact
schedule-create/detail/run-history/pause/resume/cancel plus fixed governed-memory
namespace/search/detail/propose/activate/correct/pin/expire/reject/delete and bounded extension
inventory/detail/enable/disable/revoke routes; it has no arbitrary proxy, configuration,
credential-value, extension-install/stage/invoke, or
general recovery route. Memory content is capped at 48 KiB, search at 100 results, and list/history
at 1,000 logical records/1,024 immutable revisions. Browser callers cannot supply provenance:
proposal/correction derive a stable hashed owner locator and exact content digest, reconcile it
before manual retry, and activation always records exact-revision owner approval. Schedule
creation accepts only a canonical client-proposed UUIDv7 plus a validated exact definition. The
page retains both after ambiguity; canonical storage returns an identical existing schedule without
another event and rejects same-ID semantic drift. Action-authorized creation requires typed exact
identity confirmation. Schedule history is capped at 100 rows. Extension inventory/history is capped at 1,000/1,024; enable
authority is accepted only when the complete current data-only manifest validates, the required
health capability is present, every selected axis is a subset, and the returned revision +1 grant
matches exactly. Identical completed extension transitions reconcile before dispatch. Lifecycle
mutations bind the exact rendered revision and expected
revision +1 response; cancellation and action-enabled resume require typed identity confirmation,
and ambiguity triggers an evidence re-read rather than a blind retry.
Reconciliation requires two canonical linked IDs, the exact inspected revision, an explicit
terminal conclusion, non-empty bounded external evidence, and exact mutation Origin; the browser
cannot retry the effect itself. Command DTOs reject unknown fields and
input/approval/cancellation/reconciliation retries retain stable idempotency keys. Operators must
not tunnel or expose the port; Ctrl-C destroys the listener and capability.

Usage/cost evidence is copied only from the canonical owner-authorized budget ledger. The aggregate
query binds every child through durable root lineage, accepts at most 31 days, groups terminal runs
by UTC completion day, and rejects residual reservations, unbalanced status totals, malformed UTC
buckets, or non-exact browser integers. The per-task adapter distinguishes used from reserved
microunits. Neither view labels configured provider-neutral microunits as an invoice or infers
unsupported upstream billing axes. Financial reconciliation still requires the provider's records.

### Secret disclosure in prompts or logs

Controls: opaque secret references; broker resolution at invocation; structured redaction before
persistence/presentation; tests over provider payloads, journal, logs, artifacts, and child
environments. Guided setup accepts only an environment-variable name in argv/prompts, reads its
value once after exact approval, uses the normal bounded probe/broker path, and process-tests that
the credential is absent from stdout, stderr, configuration, and rollback history.
The CLI reads `connection.json` only from a canonical, non-symlinked owner-private home, opens the
descriptor itself with no-follow semantics, validates the metadata on that exact file descriptor,
caps it at 64 KiB, and accepts only a 32-byte bearer plus a literal loopback HTTP origin. This
prevents a permissive or redirected parent directory from turning an otherwise private descriptor
check into bearer disclosure.
Dashboard memory explicitly warns that credential-category content is a reference only. The
adapter never accepts arbitrary source locators, but it cannot determine whether owner-entered
content is itself a secret; typed review, sensitivity/category metadata, owner-local exposure, and
documentation remain required controls. The owner-explicit chat `/attach` and `session send-file` paths are also
prompt-visible durable input: it opens a no-follow regular file, enforces a 256-KiB
UTF-8/text-extension ceiling, rejects NUL and symlinks, hashes the exact selected bytes, and sends
only basename/media/size/digest plus content in an untrusted frame. It never transmits the host
path, but cannot determine whether the owner selected a file that contains a secret;
documentation and the local command error boundary warn against credential files.

### Stale worker overwrites newer state

Controls: lease fencing token checked in every result transaction; monotonic revisions; expired
workers cannot commit. Existing-file edits additionally bind the complete approved arguments to
the expected current-content SHA-256 and recheck it through an `openat2`-confined regular-file
descriptor immediately before an atomic replacement. Structured edits also bind the ordered exact
old/new strings and expected non-overlapping occurrence counts; the worker verifies every count in
order and all UTF-8/size bounds before rename. Stale or ambiguous evidence fails without changing
the original.

Path lifecycle operations use a distinct non-idempotent descriptor. File moves/removals bind a
complete-content SHA-256 and every logical target; create/removal of directories is one level and
non-recursive. The worker opens parents beneath the selected root without symlink/mount crossing,
uses no-overwrite rename, and rechecks moved/quarantined bytes after the namespace transition.
Removal quarantines before unlink. A crash after the external boundary is never interpreted as
failure or retried: the effect parks as `outcome_unknown`, the task stops, and only authenticated
owner reconciliation with external evidence can settle it. A preserved quarantine is evidence,
not permission for automatic cleanup.

### Unbounded cost or resource exhaustion

Controls: durable queue caps, rate limits, concurrency limits, provider budgets, step/tool/output
limits, bounded retries, sandbox memory/CPU/time, and backpressure responses. Provider wire bodies
stop at 8 MiB, but that larger transport allowance cannot become canonical agent output: final text
is capped at 64 KiB across the complete response (including every Anthropic content block), and
normalized provider tool arguments stop at 256 KiB. The aggregate streaming counter is updated
before progress emission, so splitting a response into individually valid deltas or blocks cannot
bypass the durable-output boundary. Ordinary `mealyctl` JSON/error decoding also streams into an
8-MiB ceiling instead of trusting `Content-Length` or buffering an arbitrary local response.
Successful client envelopes must carry the exact semantic API version, and structured daemon
errors must carry that version plus bounded canonical codes and single-line terminal-safe
messages. Timeline watching applies the same 8-MiB ceiling to each complete SSE wire event before
the parser can accumulate it, requires strictly increasing matching cursor/type/body identity,
deserializes the typed event, and reserializes terminal-safe JSON instead of printing daemon bytes.
Ordinary local requests have a 30-second whole-request deadline; explicitly long drain, backup,
verification, garbage-collection, and export operations have a ten-minute ceiling, while the
resumable SSE stream reconnects from its durable cursor rather than using a whole-stream deadline.
Provider response metadata is treated as untrusted input too: retained body and header request IDs
must be bounded, trim-clean, and control-free; Responses terminal envelopes must identify the
`response` object and exact configured model; and Anthropic terminal and `message_start` envelopes
must name that same exact configured model. Provider-supplied incomplete reasons and unknown error
metadata are classified into fixed Mealy errors rather than reflected into durable records or
operator output.

### Context or memory crosses principal/workspace boundary

Controls: namespace and authorization filters before relevance scoring; context manifest records inclusion; memory provenance and sensitivity; validator gets separately compiled context.

### Journal/artifact tampering

Controls: OS-user-only storage permissions; immutable journal API; content digests; foreign keys;
backup/restore verification; bounded at-rest compression whose declared and actual decompressed
sizes, UTF-8/JSON shape, and logical digest are rechecked before dispatch/replay; optional encryption
and future hash-chain checkpoints.

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
- MCP fixtures prove network/filesystem/environment/process isolation, framing and output bounds,
  full-toolset/executable drift denial, cancellation, daemon survival, and zero-execution replay.
- The pinned real Headless Shell gate proves fresh-profile/CDP identity, rendering, safe exact-link
  same-origin navigation, exact form-free button activation plus submit-button denial, native
  text-control fill plus selected-field-only GET and POST/password/hidden-field denial, one bounded
  GUID-confined attachment plus oversized/ambient-download denial, screenshot
  bounds, non-read/WebSocket denial, model-visible citation,
  complete bundle backup/recovery, and replay after runtime deletion.
- API binds loopback only and rejects missing credentials and disallowed Origins.
- The dashboard process test proves exact Host/Origin/token enforcement, DNS-rebinding rejection,
  no daemon-bearer disclosure, fixed snapshot/timeline aggregation, exact typed command forwarding,
  stable idempotency, subject-digest binding, exact schedule identity/revision/status validation,
  malformed/oversized/arbitrary-route denial before daemon access, CSP/no-store headers, and
  lifetime cleanup.

## Deferred risks

Multi-tenant adversarial hosting needs stronger tenant encryption, resource fairness, administrative separation, and probably separate OS identities or machines. This architecture preserves principal namespaces but does not claim release-one is a hostile multi-tenant boundary.
