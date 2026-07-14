# Implementation Plan

The plan builds vertical proofs. A phase is complete only when its exit gate passes; creating empty modules is not progress.

Current status: Phases 0 through 7 are implemented. Their gates cross the real HTTP, process,
SQLite, artifact, outbox, and SSE boundaries. The process suites hard-kill the daemon across
admission, provider dispatch, and read-tool preparation, then prove fenced recovery, exact budget
settlement, and recorded-only replay. Phase 3 additionally crosses approval, sandbox dispatch,
external mutation, outcome, and observation boundaries and proves denial, expiry, cancellation,
unknown-outcome reconciliation, and effect-aware recorded replay without duplicate mutation.
Phase 4 adds task admission criteria/risk, deterministic and fresh-context validation, validation-
gated success, bounded child authority/budgets/results, exclusive resource claims, lineage-aware
timelines, and owner-inspectable validation evidence.
Phase 5 adds cited immutable compactions, governed memory lifecycle and provenance, owner/workspace
namespace enforcement, deterministic FTS5 retrieval with degraded fallback, untrusted context
projection, content deletion with audit tombstones, and restart-safe recorded replay.
Phase 6 adds data-only digest-pinned extension packages, explicit immutable grants, supervised
one-shot RPC, crash/upgrade/revocation evidence, signed external-subject channel bindings, brokered
HMAC keys, replay reservations, and signed durable callback delivery across restart.
Phase 7 adds owner service installation, schema-versioned retention configuration and rollback
history, safe mode, bounded clean/forced drain evidence, operational gauges and request traces,
complete online backup with optional authenticated-encrypted secrets, isolated fresh-home restore
verification, scoped exports, age/reference-safe artifact GC, automatic pre-migration snapshots,
corrupt-store forensic preservation, and explicit platform sandbox conformance reporting.
Release review additionally closes durable task pause/resume fencing, atomic input-capacity
backpressure, configured run/concurrency limits across every required scheduler dimension,
deterministic jittered retry, a data-only skill contract and owner lifecycle with bounded cited
resource loading, live provider routing evidence with
same-trust fallback checks, complete secret-free export, and task/run/attempt trace identity.

## Phase 0: Executable domain skeleton

Deliver:

- workspace and crate dependency rules;
- typed IDs and task/effect state machines;
- transition and property tests;
- initial SQLite migration with journal, aggregate sequence, session inbox, tasks, runs, leases, effects, and outbox;
- deterministic clock/ID test adapters.

Exit gate: domain tests reject invalid transitions, and a real SQLite transaction atomically commits a task change, journal event, and outbox row.

## Phase 1: Durable admission and scheduler

Deliver:

- loopback API authentication;
- session creation and idempotent input admission;
- durable FIFO promotion;
- work lease claim, heartbeat, expiry, and fencing;
- timeline query/SSE cursor;
- startup recovery for leases and pending outbox rows;
- `mealyctl session create|send|watch|status`.

Exit gate: kill the daemon after acknowledgement but before promotion; restart and observe exactly one promoted input and a continuous timeline.

## Phase 2: Provider and read-only loop

Deliver:

- provider capability port and deterministic fake provider;
- context epochs and context manifests;
- bounded agent loop with one read-only tool;
- normalized model attempts and usage;
- artifact store for large tool/provider output;
- cancellation and budget limits.

Exit gate: public-API scenario runs fake model → read tool → final answer; replay uses recorded results without provider/tool calls.

Status: complete. `phase2_read_only_loop`, `phase2_attempt_recovery`, and `phase2_cancellation`
exercise the public API and real daemon process. Replay verifies the complete state/journal/timeline
and artifact graph and fails closed under targeted evidence corruption without making live calls.

## Phase 3: Effect and approval proof

Deliver:

- tool descriptors and policy evaluation;
- sandbox executor process protocol;
- effect intent, approval subject hash, dispatch, outcome, and reconciliation;
- stable idempotency keys;
- waiting/resume across restart;
- unknown-outcome operator workflow.

Exit gate: crash injection at every line between intent creation, dispatch, external mutation, result receipt, and commit. Each case produces the expected retry, success, failure, or `outcome_unknown` state without duplicate non-idempotent mutation.

Status: complete. The approval-gated fixture write binds its schema-normalized arguments,
capability, target, executable identity, policy version, and expiry into one durable subject. The
ledger atomically parks/resumes the agent loop, reserves and settles tool/output budgets, dispatches
only through the least-authority Bubblewrap worker, records terminal or unknown evidence, and
supports authenticated idempotent approval/reconciliation commands through API and CLI. The
`phase3_effect_approval` process suite proves denial, exclusive expiry, cancellation revocation,
cold restart before and after approval, prepared-before-dispatch recovery, post-mutation ambiguity,
terminal-before-observation recovery, one external mutation, and recorded-only replay with zero
live calls.

## Phase 4: Validation and delegation

Deliver:

- success criteria and risk policy;
- deterministic validator and fresh-context model validator;
- child run lineage, capability intersection, separate budgets, and structured return;
- resource conflict claims;
- validation evidence in task completion.

Exit gate: parallel child runs cannot both claim one write scope; stale child result is fenced; medium-risk task cannot succeed without passing validation or a durable waiver.

Status: complete. Root tasks atomically persist typed capability ceilings, explicit success
criteria, risk, validation policy, and lineage. Low-risk reads run deterministic evidence checks;
medium-risk writes create a fresh read-only validator task/run and cannot cross the schema success
gate without a passing record or waiver. Validation survives restart without duplication and is
visible in task/timeline projections. Delegation atomically intersects parent, requested, and
current-policy authority; reserves and settles a separate child budget; fences structured results;
and rejects out-of-scope or concurrently owned resource claims. The production agent loop now
exposes that boundary as `agent.delegate`: it atomically parks the parent, schedules an isolated
read-only child with depth zero, resumes the parent with `delegation://result`, propagates parent
cancellation, and exposes owner-bound list/status views. Public-process tests prove root and child
recorded-only replay, in-flight cancellation, context isolation, and exact budget settlement in
addition to the original Phase 4 storage exit gate and v7-to-v8 preservation.

## Phase 5: Memory and compaction

Deliver:

- structured compaction carry-forward and source citations;
- memory proposal/revision lifecycle;
- namespace/sensitivity/retention policy;
- SQLite FTS5 retrieval and degraded operation without embeddings;
- inspection, correction, export, and deletion CLI.

Exit gate: compaction preserves typed unresolved effects/constraints, source history remains queryable, and a cross-principal memory leak test fails closed.

Status: complete. Compaction commits validate exact source cursor/event/digest citations, require
typed goals and safety constraints, and cannot omit canonical pending approvals or effect outcomes.
Memory proposals retain immutable source evidence and support explicit activation/rejection,
superseding corrections, pin/expiry/deletion, owner export, and active-only FTS5 indexing with a
canonical fallback and rebuild path. Context manifests expose exact memory revision/source and
compaction provenance while labeling retrieved memory as untrusted evidence. The Phase 5 process
scenario crosses the authenticated API and real daemon, retrieves memory and compaction evidence,
deletes memory content, hard-restarts, and still completes recorded-only replay; storage/backend
tests prove sensitive-promotion authorization and fail-closed principal/channel/workspace scope.

## Phase 6: Extension and channel boundary

Deliver:

- manifest schema and digest pinning;
- supervised extension host with scoped RPC;
- one sample out-of-process tool extension;
- one external channel adapter with signature verification and durable outbox delivery;
- crash/upgrade/revocation lifecycle.

Exit gate: hostile extension fixtures cannot read undeclared secrets, write outside grants, forge an effect outcome, or stop `mealyd`; duplicate channel webhooks admit one input.

Status: complete. Extension installation and upgrade inspect exact manifest, executable, and
runtime digests before any code runs. Health and granted read-only capabilities execute through a
bounded empty-environment Bubblewrap host; dispatch evidence precedes launch and every valid output
or classified failure is terminally recorded. The sample extension process proves ambient secret,
filesystem, environment, network, forged-response, crash, fresh-grant upgrade, revocation, and
restart behavior. The signed webhook adapter creates a dedicated principal-bound session and
owner-only key file, verifies exact raw bodies and timestamp/nonce HMAC framing before JSON parsing,
reserves replay evidence before inbox admission, and reuses the existing durable outbox for signed
callbacks. Its process suite proves one admission for an exact duplicate, rejection of nonce reuse,
forgery, stale timestamps, and wrong subjects, callback retry across hard restart with a stable
delivery ID, key destruction, terminal revocation, and v9-to-v10 preservation.
The later native MCP stdio slice reuses this fail-closed boundary without treating protocol
metadata as authority: exact executable/full-toolset/full-definition/schema grants, fresh
no-network Bubblewrap sessions, protocol/result bounds, cancellation, revocation, cited durable
evidence, and execution-free replay are covered by fixture, CLI, and real-daemon process tests.
HTTP MCP, resource mounts, credentials, and effectful MCP remain outside this completed subset.

## Phase 7: Operational hardening

Deliver:

- service installation, doctor, safe mode, graceful drain;
- backup, restore verification, export, retention, garbage collection;
- migration snapshot suite and corrupt-database forensic backup;
- metrics/traces and admin health views;
- platform sandbox conformance lanes.

Exit gate: restore into a fresh home passes integrity/scenario checks; corrupt DB handling preserves original files; supported OS lanes prove or explicitly deny each policy profile.

Status: complete. The authenticated admin API and `mealyctl` expose status, metrics, doctor, drain,
complete backup, restore verification, complete/scoped export, and GC. Backup manifests cover the online
SQLite snapshot, configuration, every canonical artifact, configured skill package, and configured
content-addressed MCP executable, plus every file and executable-mode bit in a configured
content-addressed browser bundle; secret inclusion is explicit and
uses Argon2id-derived XChaCha20-Poly1305, while fresh-home verification authenticates the decrypted
identity against restored canonical state. Startup snapshots every older supported schema before
its transactional migration and preserves corrupt databases plus WAL/SHM sidecars before failing.
Safe mode starts no dispatch workers and rejects mutations while retaining recovery operations.
Clean drain checkpoints and exits zero; a blocked provider proves the bounded status-2 path records
durable `forced` evidence. Doctor and CI lanes report Linux Bubblewrap conformance and explicitly
deny unavailable profiles/platform adapters. `phase7_operations` crosses the actual daemon/API
process boundary for the exit gate; maintenance, migration, artifact, API, and configuration unit
tests cover tamper, wrong-passphrase, prior-schema, GC, request-ID, and marker invariants.
The same process suite covers pause/resume revision and lease fencing, complete archive export, and
the public doctor fallback proof; scheduler/session units enforce durable concurrency and queue
capacity while provider/resource/extension guards enforce adapter-side limits.

## Productionization slice: rendered-browser research

Status: complete for the read-only Linux x86_64 subset. The owner workflow downloads only an exact
size/SHA-pinned Chrome Headless Shell archive, performs no-network bundle/product inspection,
publishes a complete content-addressed no-symlink inventory, and requires a live CDP/render
self-test before activation. Each `browser.snapshot` call uses a fresh profile and private
Bubblewrap network namespace, with Chrome proxy traffic relayed over a Unix socket to the trusted
host destination/DNS/IP/GET/HEAD/byte/time policy and narrowed per call to the initial exact origin.
Cross-origin redirects, subresources, and followed/activated links fail closed. CDP independently rejects non-read methods and
auth, denies ambient downloads, and blocks WebSocket/WebTransport/QUIC/direct sockets. Output is bounded
normalized accessibility evidence plus optional PNG; one accessible link can be followed only as
a direct GET, or one exact native form-free `type=button` can be activated through a captured
pristine click method. One exact native non-password textbox/searchbox can instead be filled through
a captured value setter without page events; an optional same-origin GET is constructed from only
that named control after method/action/target validation. Hidden/sibling controls, submit handlers,
POST forms, and password inputs fail closed.
One alternative exact accessible link can be captured as an attachment: only same-origin GET,
CDP GUID naming in the ephemeral profile, bounded progress/total/file size, `NOFOLLOW`, and at most
512 KiB of digest/base64 evidence are accepted; no owner path is written. Capability promotion,
delegation, context epochs, policy evidence, durable artifacts,
recovery, replay, safe mode, CLI lifecycle, complete backup, migration reconstruction, service
cgroup limits, and CI/tag gates all cover the new adapter. Real Chrome tests prove rendering,
non-read/upgrade denial, model citation, and replay after deleting the runtime.

This slice intentionally does not implement arbitrary click/keyboard events, POST or multi-control
forms, uploads, unbounded/owner-path downloads, persistent profiles, or personal-profile attachment. Those are effectful
capabilities requiring a new approval/effect-ledger contract rather than a flag on the read tool.

## Productionization slice: interactive operations dashboard

Status: complete for the owner-local conversation/control, unknown-effect recovery, schedule,
governed-memory, and extension-lifecycle subsets. `mealyctl dashboard` preflights
six typed canonical operational projections, binds one random numeric-loopback port for its
foreground lifetime, and renders provider health/pressure, status, doctor checks, recent sessions,
pending exact approvals, schedules, tools, storage, and failure evidence. A fixed typed adapter can
also create/select sessions, submit bounded queue/steer/interrupt input, poll a live 200-event
timeline, resolve a rendered subject by exact digest, and request cooperative cancellation of its
active task. A fixed recovery extension loads exact effect/attempt projections and reconciles only
a linked pair that remains `outcome_unknown`, with exact revision, explicit terminal conclusion,
non-empty 32-KiB-bounded external evidence, confirmation, and stable idempotent delivery. It never
redispatches or cleans external state. Input/approval/cancellation/reconciliation commands retain
stable idempotency keys.

The usage-history projection reads an exact-owner inclusive/exclusive range of at most 31 days,
binds root/delegated/validation runs through canonical lineage, requires terminal zero-reservation
settlement, and groups non-empty UTC completion days. The dashboard uses a trailing 30-day range
and validates ordering, status balance, timestamps, per-field and aggregate JavaScript-safe sums.
Schema 15 supplies a partial terminal-completion index and the canonical query requires that index,
with v14 forward-migration and query-plan regression evidence.
The task-usage extension loads one exact owner-authorized canonical task projection from a typed
UUID. It separates settled/charged and active-reserved provider-neutral cost microunits alongside
model/tool/delegation calls, retries, tokens, and output bytes; validates final-content digest,
criteria/validation identities, JavaScript-safe integers, and zero terminal reservations; and
explicitly refuses to infer an external invoice or unsupported billing dimensions.

The schedule extension creates from an exact existing session and immutable definition, loads the
canonical definition plus a bounded newest-first occurrence history, and exposes pause, resume,
and terminal cancel. A client-proposed canonical UUIDv7 is both resource identity and durable
creation key: exact replay returns the existing schedule without another event, while different
semantics under that identity conflict. The page retains that key across ambiguity and requires a
typed confirmation for action-authorized creation. Every lifecycle mutation binds the rendered
revision, accepts only the same schedule/requested status at revision +1, and performs no automatic
retry after ambiguity. Cancellation and resuming an action-authorized schedule require typed
schedule-ID confirmation.

The governed-memory extension lists or searches one exact authorized namespace, renders a complete
bounded immutable revision/provenance history, proposes inactive records, and exposes explicit
activate, correct, pin/unpin, expire, reject, and delete/scrub commands. Every read and mutation is
a strict Origin-checked POST so workspace identities and search text do not enter URLs. Proposal
and correction provenance is adapter-derived from a stable browser command key and the exact
content digest; preflight reconciliation makes manual duplicate delivery safe. Activation always
forwards exact-revision owner approval, lifecycle mutations are revision fenced, and ambiguous
responses require a re-read. Browser memory content is capped at 48 KiB, search at 100 results,
logical lists at 1,000 records, and immutable history at 1,024 revisions. Raw credentials remain
out of scope: the credential category accepts references, not secret values.

The extension slice lists up to 1,000 records, validates up to 1,024 immutable manifest revisions,
and renders the complete current data-only manifest, health evidence, and active grant. Enable
choices are derived only from that manifest: the mandatory health capability plus explicitly
selected capabilities, canonical mount mappings, destinations, opaque secret references, and
process authority. A preflight binds the exact current revision and reconciles only an identical
already-enabled revision +1 result; otherwise a successful health probe and exact returned grant
are required. Disable and terminal revoke have the same revision/reconciliation boundary. Package
install/stage, installation roots, upgrades, and arbitrary invocation remain on the reviewed CLI.

The daemon bearer never crosses into browser content. An independent 256-bit capability, exact
Host plus exact mutation-Origin checks, canonical UUID parsing, strict/size-bounded DTOs,
constant-time comparison, CSP/no-store/frame/resource headers, bounded concurrency, generic backend
failures, an 8 MiB streamed daemon-response ceiling, and public-process/real-daemon adversarial
tests cover the boundary. There is no arbitrary proxy or configuration, credential,
extension-package/install/stage/invoke, or general recovery route.

## Productionization slice: OpenRouter preset

Status: complete for deterministic compatibility evidence. The stopped-daemon preset uses the
existing hardened stateless Responses adapter, official API-base/key defaults, `store: false`, and
the same live bounded write-after-probe activation. Credential-scoped `/models/user` discovery
reflects account privacy/provider/guardrail policy, emits only text/tool-capable models, normalizes
limits, converts representable posted USD/token prices exactly, and marks fixed/media/search/
reasoning/cache charges unsupported rather than pretending two token rates settle them. Process
tests prove request shapes, bounds, secret isolation, atomic activation, and failure redaction.
OpenRouter still labels Responses beta; a credentialed real-account smoke remains release evidence.

## Productionization slice: guided clean-home setup

Status: complete. `mealyctl setup` atomically installs the shared typed non-secret default into a
clean private home, selects `OpenAI`, Anthropic, `OpenRouter`, or a credentialless literal-loopback
provider, and prompts only for bounded model/limit/price values. Remote keys come from a named
environment variable and never enter argv, prompts, JSON, configuration, or history. The wizard
previews the exact settings and config digest, requires an exact `APPROVE` phrase or a complete
flagged `--approve` invocation, then reuses the normal no-proxy/no-redirect bounded model probe,
conflict-safe broker, and atomic rollback-preserving activation. Success prints exact
daemon/doctor/chat commands; staged probe skipping is conspicuously labeled. Unit and process tests
cover interactive local setup, clean-home remote setup, secret isolation, denial, probe shape, and
handoff output.

## Productionization slice: structured exact workspace edits

Status: complete for bounded in-place text changes. `workspace.replace_file` v2 retains the
approval-bound current-file SHA-256 and complete-content compatibility, while adding exactly one to
16 ordered exact old/new-text edits with per-edit expected non-overlapping occurrence counts. The
normalizer rejects mixed forms, extra fields, empty old text, invalid counts, and excessive input.
The confined worker reads only an `openat2`-beneath regular file, verifies digest and every count,
applies edits in order, enforces UTF-8/output bounds, and uses the existing private staging,
fsync, atomic-rename, and directory-sync boundary. Mismatch leaves the original unchanged. Unit,
sandbox, provider-process, validation, and replay proofs cover both compatibility and structured
paths. Fuzzy matching remains outside this authority.

## Productionization slice: governed workspace path lifecycle

Status: complete for one exact operation per explicit `/manage` turn. The
`workspace.manage_path` v1 schema admits only create-directory, digest-preconditioned no-overwrite
file move, digest-preconditioned bounded-file removal, or empty-directory removal. Policy binds
the configured writable workspace, normalized arguments, both move targets, worker digest, run,
owner binding, expiry, and fixed `write:workspace:manage` capability. The Linux worker resolves
only safe existing parents with `openat2`, uses `mkdirat`, `renameat2(RENAME_NOREPLACE)`, or
non-recursive `unlinkat`, synchronizes namespace changes, and rechecks moved/quarantined file bytes.
Removal quarantines under an effect/attempt-specific name before unlinking. The descriptor is
non-idempotent/reconcile-only, so generic crash recovery parks ambiguity rather than redispatching.
Unit policy/normalization tests, adversarial Bubblewrap coverage of all four operations, a public
provider approval/validation/replay proof, durable replay-contract validation, and capability-
ceiling checks cover the slice. Recursive tree operations, directory moves, overwrite, chmod, and
fuzzy matching remain outside this authority.

## Productionization slice: Discord one-human DM

Status: complete for the least-authority REST profile. Setup verifies the API v10 bot, exact
type-1 DM, and sole non-bot recipient twice around a 128-bit challenge before brokering a
digest-pinned token and creating a dedicated session. Canonical decimal-string snowflakes avoid
signed narrowing. Bounded polling backfills full newest-first pages to the durable floor, rejects
gaps/duplicates/malformed history, reserves every message before effect, and advances only with a
terminal receipt. The same queue/steer/interrupt and exact-subject approvals feed the core inbox.
Outbound delivery suppresses mentions/embeds, caps content, derives an enforced nonce from the
durable outbox, respects shared platform rate delays, and parks ambiguous acceptance. Unit/store,
CLI, and public-process tests cover a 106-message page gap, attacker and attachment rejection, hard
restart, 429 retry/nonce reuse, progress/final delivery, credential isolation, and revocation.

Attachments, guild channels, group DMs, Gateway presence, and multi-user routing remain outside
this profile; Telegram remains the bounded text-document channel.

## Deferred until the core proof

- broader dashboard administration beyond the completed conversation/approval/task-control,
  task-usage/cost, unknown-effect-reconciliation, schedule-creation/lifecycle, governed-memory, and
  extension-lifecycle subsets;
- Discord guild/group workflows beyond the completed exact one-human DM profile;
- semantic/vector memory;
- plugin marketplace;
- distributed scheduler;
- multi-user product UX;
- effectful browser interaction and personal-profile trust mode;

These features consume established APIs. They must not introduce alternate state, queue, policy, or approval paths.
