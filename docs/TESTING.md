# Testing and Verification

## Test layers

### Domain unit and property tests

Fast, infrastructure-free tests cover state transitions, capability intersections, approval subject hashes, recovery classification, budget arithmetic, resource-claim ordering, and context mandatory-item rules.

Property examples:

- terminal task states never become active;
- aggregate sequence never decreases or duplicates;
- stale fencing tokens never authorize a commit;
- changing any effect subject field changes the approval digest;
- child capabilities are never broader than parent and profile grants;
- non-idempotent unknown effects never classify as automatic retry.

### Storage integration tests

Use real SQLite files, WAL, foreign keys, concurrent connections, busy timeouts, and migrations. Mock repositories cannot prove transaction or locking semantics.

Required checks:

- canonical row + event + outbox atomicity;
- rollback leaves none of the three;
- idempotent duplicate input admission;
- lease claim races and expiry;
- artifact rename/link crash cleanup;
- migration from every supported snapshot;
- backup and restore integrity.

### Process-boundary tests

Spawn the real executor/extension protocol. Verify framing, malformed messages, size limits, cancellation, timeout, stdout/stderr pressure, secret minimization, worker death, and daemon survival.

GitHub's Ubuntu 24.04 runner enables AppArmor's unprivileged-user-namespace restriction, which can
make Bubblewrap fail while bringing up its private loopback device with `RTM_NEWADDR: Operation not
permitted`. The CI and tag workflows install and directly load only Noble's packaged
`bwrap-userns-restrict` extra profile, verify both stacked profiles are enforced, explicitly retain
`kernel.apparmor_restrict_unprivileged_userns=1`, ensure
`kernel.unprivileged_userns_clone=1` when that older switch exists, and require a private-network
Bubblewrap probe before tests. A normal production host follows the same reviewed distro-profile
path or a dedicated host policy and must pass `mealyctl doctor`; globally weakening the kernel
mitigation is not an application setup default.

### Public-API scenarios

Scenarios start `mealyd`, drive versioned API commands, watch SSE, and assert durable database/artifact state only through supported inspection helpers.

The Phase 1 scenario at `apps/mealyd/tests/phase1_recovery.rs` currently proves authenticated
admission, hard process death before promotion/outbox delivery, identity-preserving restart,
exactly-one promotion, outbox resumption, stable idempotent receipts, and cursor-resumed SSE. The
storage scenarios in `crates/mealy-infrastructure/tests/phase1_runtime.rs` and
`outbox_delivery.rs` cover claim races, live expiry, stale result fencing, all three input delivery
modes, and outbox ownership recovery.

The Phase 2 process suites at `apps/mealyd/tests/phase2_read_only_loop.rs`,
`phase2_attempt_recovery.rs`, and `phase2_cancellation.rs` prove the bounded fake-provider → read
tool → final loop, content-addressed artifact output, cooperative cancellation, timeout
containment, immediate startup recovery, retry lineage, exact reservation settlement, and
recorded-only replay. Their corruption matrix covers normalized responses and usage, lifecycle
ordering, successful-row error classes, policy and descriptor capability evidence, artifact
producer metadata and blob presence, checkpoints, exact operation payloads, per-aggregate journal
sequence chains, terminal graph state, and journal-to-timeline links. Every replay assertion also
checks that no live provider or tool call occurred.

`apps/mealyd/tests/real_provider.rs` crosses the public process boundary with independent mock
wire servers for `OpenAI` Responses and Anthropic Messages. It verifies protocol-specific headers,
request/tool normalization, terminal and streaming settlement, durable retry timing, endpoint
health/history, active cancellation, workspace/web/mutation integrations, and zero-dispatch
replay. Its mixed-protocol scenario makes the Responses primary reject definitely, dispatches the
authorized retry through streaming Anthropic Messages, and proves both exact endpoint identities
and brokered credentials remain isolated. Its two-turn scenario verifies the exact chronological
developer/user/assistant/user wire projection and recorded replay. Storage/compiler units prove
the 32-turn/512-KiB discovery bounds, owner denial, compaction cutoff, and mandatory-latest-input
reservation; the workspace-revocation restart scenario proves epoch rotation removes old
conversation evidence. The delegation scenarios make the provider launch a real durable child,
prove its wire context excludes the parent's original conversation, inspect its exact owner-bound
authority/budget/result projection, resume the parent through recorded `delegation://result`
evidence, and independently replay both tasks without live calls. A second scenario cancels the
parent while the child provider request is in flight and proves cancellation propagation, child
and parent terminal state, reservation settlement, and exactly two provider requests. Adapter
logic rejects parallel or undeclared tools and bad event ordering;
focused unit tests cover request shapes, cross-turn roles, tool normalization, malformed/cached
usage, oversized content, response-body canaries, and stalled streams. The normalized-output
regressions specifically split more than 64 KiB of Anthropic text across two individually valid
stream blocks and require rejection before the violating delta is emitted; a separate Responses
case places more than 256 KiB in one syntactically valid function argument object and requires
rejection before model-result persistence. Response-identity regressions require the Responses
`object` discriminator and exact configured model, require the exact configured Anthropic model in
both JSON and streaming `message_start`, reject unsafe body IDs, discard unsafe request-ID headers,
and prove that an incomplete-reason secret/control canary is never reflected in the adapter error.

`apps/mealyctl/tests/provider_configuration.rs` crosses the client process boundary for provider
onboarding. Clean-home setup scenarios drive the interactive provider/model/limit prompts and
exact `APPROVE` phrase, verify denial creates no provider state, and prove a fully flagged remote
setup initializes the shared default, performs a real bounded streaming probe, brokers the key,
keeps secret bytes out of stdout/stderr/config, retains rollback history, and prints exact
daemon/doctor/chat handoff commands. Composition-level onboarding scenarios prove a clean
`--configure-only` transaction, reject a second run without `--reconfigure` while preserving exact
configuration bytes, and prove the implicit `$HOME/.mealy` remains the exact same state after a
working-directory change while `--home` and `MEALY_HOME` overrides remain exact (including an
explicit home without `HOME`). They also discover a live OpenRouter account catalog, exclude
paid/incomplete models,
derive exact zero prices and limits for an eligible `:free` model, perform its bounded streaming
probe, and keep the credential out of all output/config. Both official subscription-client
fixtures are also exercised through `onboard`, including executable digest pinning and API-key
environment exclusion. The suite also proves atomic credential brokering and protocol-specific activation probes, plus
read-only live OpenAI/Anthropic model discovery with exact authentication headers, filtering,
Anthropic cursor pagination, token-limit normalization, and local record/response bounds. Its
probe validators require the terminal protocol discriminator, bounded safe identity, and exact
owner-selected model before activation, for both JSON and SSE variants. They also require a usable
bounded text decision with no tool call, consistent usage within configured limits, matching
Responses preview/terminal text, and ordered/index-matched Anthropic stream blocks. A process
regression proves a wrong terminal model cannot publish configuration or broker state. Its
literal-loopback preset proof verifies discovery and Responses activation send no authorization,
persist no credential, create no broker, support a same-boundary fallback, and reject remote
credentialless activation before mutation. Mixed-protocol chain cases remove one exact fallback
without reordering the rest or deleting its broker key, preserve a compatible chain across primary
credential rotation, inspect the validated chain without credential resolution, and reject an
incompatible primary before config or broker mutation. All failure paths redact credentials and response
bodies.

`apps/mealyctl/tests/skill_configuration.rs` crosses the client process boundary for data-only
skills. It proves read-only inspection, no mutation without approval, immutable digest publication,
installed-but-disabled staging, source-package independence, exact-digest activation fencing,
update-to-disabled semantics, retained prior revisions, list/status verification, tool-reference
non-authority, and installed-byte tamper failure. Infrastructure tests reject undeclared files,
changed assets, symlinks/unsafe inventory, and exercise bounded UTF-8/base64 passive-resource
reads. The real-provider process suite proves enabled instructions and manifest provenance enter
the actual baseline while resource content does not, then performs a `skill.read_resource` call,
requires its `skill://` citation, and verifies recorded replay with zero live calls. Backup tests
prove referenced skill files are manifest-covered and restored-verifiable.

`crates/mealy-infrastructure/tests/mcp_stdio.rs` runs a real native stdio fixture through the
Bubblewrap boundary. It proves exact `2025-11-25` initialization, initialized notification,
paginated full discovery, schema-pinned invocation, an empty environment, absent host
`/etc/passwd`, denied network/child-process authority, malformed or extra stdout rejection,
bounded stderr pressure, wrong-version failure, complete-toolset drift denial, executable-tamper
denial, and cooperative cancellation followed by termination. Application units reject external
JSON Schema resolution, required task support, invalid arguments, digest drift, and non-canonical
grants.

`apps/mealyctl/tests/mcp_configuration.rs` crosses the stopped-home client boundary. It proves
read-only listing, approval-before-execution/mutation, exact selected-tool publication,
disable/re-enable/revoke semantics, live tool-set verification, and retained configuration
history. The `configured_mcp_tool_is_sandboxed_model_visible_cited_and_replayable` scenario in
`apps/mealyd/tests/real_provider.rs` starts the real daemon, advertises the exact model-visible MCP
schema, executes a sandboxed call, requires an `mcp://` citation, removes the installed executable,
and still verifies recorded-only replay with zero provider or tool calls. Maintenance tests prove
complete backups, isolated verification, and cross-schema home reconstruction preserve exact MCP
bytes and executable permissions.

The `linux-browser-conformance` CI lane downloads only the repository-pinned Chrome Headless Shell
archive through `scripts/fetch-browser-runtime.sh`, verifies its exact HTTPS artifact size and
SHA-256, and sets `MEALY_BROWSER_BUNDLE` for three opt-in real-process suites.
`crates/mealy-infrastructure/tests/browser_runtime.rs` proves complete bundle identity, isolated
CDP `1.3`/product startup, private proxy routing, rendered accessibility output, exact accessible
GET-link following, exact native form-free button activation, exact text/search fill, selected-
field-only same-origin GET submission, hidden-field exclusion, submit-button/POST/password denial,
one exact CDP GUID-named attachment capture with `NOFOLLOW`/size/digest/base64 evidence, PNG bounds,
and that hostile page POST/WebSocket or ambient download attempts never reach the origin/filesystem.
Download progress accepts only non-negative integral CDP JSON numbers (including valid floating or
exponent encodings) within exact IEEE-754 range; fractions, negatives, and oversized values fail
closed. Focused proxy regressions churn the complete 256-connection per-call budget sequentially,
prove the excess connection is closed, prove a 32-connection concurrency lease cannot be widened,
and reclaim completed thread handles before browser shutdown. The real suite must pass repeated
fresh-process runs after any browser-protocol fix.
`apps/mealyctl/tests/browser_configuration.rs` crosses the stopped-home CLI boundary and
proves inspect/add approval, immutable publication, live render preflight, list,
disable/re-enable/revoke, web-authority dependency, and retained rollback bytes.
`configured_browser_is_rendered_isolated_cited_and_replays_without_live_chrome` in the daemon
real-provider suite proves exact model schema exposure (including bounded attachment capture), safe GET-form filling, rendering through
the normal agent loop, artifact-backed screenshot evidence, URL citation, and complete
zero-live-call replay after the
browser bundle is deleted. Maintenance fixtures cover every bundle file and executable-mode bit in
complete backup, isolated restore verification, and migration reconstruction. These large tests
are ignored in ordinary local runs but mandatory in CI and tag release workflows.

`apps/mealyctl/tests/memory_workflow.rs` proves the concise owner-memory path makes two distinct
authenticated requests: an exact content-digest-cited private proposal followed by bound
`owner_approval` of that revision. It also proves omitted `--approve` cannot start the workflow and
that a post-proposal activation conflict reports the durable memory/revision IDs for recovery. CLI
parser tests cover every inline chat memory shape, while the PTY test proves the added namespace
discovery preserves non-blocking chat admission and clean `/quit` behavior. The two-turn real
provider scenario searches the canonical first turn through the public endpoint and checks its
session/task identity, complete user digest, and 512-byte excerpt ceiling; it also verifies the
model-visible baseline permits only a clearly labeled `/remember` suggestion. The Telegram and
Discord process scenarios search for completed remote-only markers using the local credential and
prove the principal/channel-binding predicate prevents a cross-transport transcript leak.

The Phase 3 suite at `apps/mealyd/tests/phase3_effect_approval.rs` drives the authenticated public
approval/effect commands and a real Bubblewrap worker. It proves deny, expiry, cancellation
revocation, exact command deduplication/conflict behavior, budget settlement, and the crash matrix
from parked intent through preparation, dispatch, external mutation, outcome commit, observation,
and reconciliation. Successful and reconciled tasks replay from recorded effect evidence with zero
live provider/executor calls, while attempt counts and workspace bytes prove that unsafe work was
not repeated.

The Linux sandbox integration additionally proves ordered exact-text replacement: one approved
request applies multiple edits with explicit occurrence counts, while a count mismatch returns
`patch_precondition_mismatch` and leaves the target byte-for-byte unchanged. The real-provider
`explicit_edit_applies_one_digest_pinned_patch_and_replays_without_redispatch` scenario crosses the
model-visible v2 schema, normalized patch, exact approval, content-digest check, worker execution,
fresh validation, and recorded-only replay with one filesystem mutation and no redispatch.

The same sandbox integration exercises all four `workspace.manage_path` shapes. It proves exact
directory creation and empty-only removal; digest-matched file move; destination no-overwrite;
digest-matched quarantine-before-unlink removal; stale-precondition preservation; and denial of
symlink sources/targets without touching outside bytes. The real-provider
`explicit_manage_moves_one_digest_matched_file_and_replays_without_redispatch` scenario crosses the
model-visible one-of schema, sorted two-target approval, non-idempotent dispatch, fresh independent
validation, durable replay-contract reconstruction, and execution-free replay with exactly one
filesystem namespace mutation. A second ordinary turn in the same session proves historical
action-prefixed input cannot reselect or inherit mutation authority. Generic effect-ledger crash tests apply its declared
`NonIdempotent`/`Reconcile` matrix and prove ambiguous attempts park for owner reconciliation rather
than redispatch.

The Phase 4 process suite at `apps/mealyd/tests/phase4_validation.rs` runs a deterministic low-risk
validator and a fresh-context medium-risk validator through the public task API, then hard-restarts
the daemon and proves stable validation identity, zero duplicate records, read-only validator
authority, child lineage, validation-gated success, and recorded-only replay. SQLite tests prove
three-way child capability intersection, separate delegated-run budget reservation/settlement,
out-of-scope claim rejection, exclusive write-scope arbitration, stale child-result fencing,
lineage-aware timeline visibility, and v7-to-v8 data preservation. The agent-facing process proofs
add atomic parent parking/child creation, scheduler claim, isolated context compilation,
owner inspection, cancellation propagation, and root/child replay coverage.

The Phase 5 process suite at `apps/mealyd/tests/phase5_memory_context.rs` creates a cited typed
compaction and an activated governed memory through the authenticated API, then proves both are
selected into model context with exact owner-inspectable provenance and explicit untrusted-memory
labeling. It completes recorded-only replay before and after memory content deletion, hard-restarts
the daemon, and proves the same replay and provenance remain available without live model/tool
calls. SQLite tests cover proposal/activation/rejection/correction/pin/expiry/deletion transitions,
sensitive owner authorization, active-only FTS5 synchronization and degraded fallback, index
rebuild, immutable citations, canonical approval/effect carry-forward, typed goal/safety retention,
v8-to-v9 preservation, and cross-principal/channel/workspace denial.

The Phase 6 process suites at `apps/mealyd/tests/phase6_extension_boundary.rs` and
`phase6_channel_boundary.rs` cross the authenticated administration API, unauthenticated-but-signed
ingress, SQLite replay registry, owner-only secret broker, real Bubblewrap extension worker, and a
real HTTP callback receiver. They prove manifest/executable/runtime digest pinning, least-authority
grant replacement, health-gated enable, schema-bound RPC, secret/environment/filesystem/network
isolation, forged-response and crash containment, upgrade, terminal revocation, raw-body HMAC
verification, stale/forged/wrong-subject rejection, exact duplicate admission, nonce replay denial,
and signed outbox delivery after a hard daemon restart. Storage tests cover immutable invocation and
manifest evidence, revocable principal/channel registries, replay reservation recovery, active-only
outbound routing, secret-file permissions/deletion, and v9-to-v10 preservation.

`apps/mealyd/tests/telegram_channel.rs` separately proves live bot verification, exact private
sender/chat allowlisting, bounded text attachments, cursor restart, remote scheduling, delivery
retry, and terminal revocation. `apps/mealyd/tests/discord_channel.rs` runs the daemon against a
real loopback HTTP fixture implementing Discord's API shape. It verifies bot/type-1-DM/recipient
setup, token isolation, canonical string snowflakes, a newest-first 106-message page gap recovered
without loss, reserve-before-admission, exact sender rejection, attachment rejection, hard restart,
429 `Retry-After`, stable nonce reuse, mention suppression, progress/final delivery, transcript
transport isolation, secret deletion, and terminal revocation.

The Phase 7 process suite at `apps/mealyd/tests/phase7_operations.rs` starts real daemon processes
for safe mode, clean drain, corrupt-open failure, and a provider call deliberately held beyond a
100 ms drain deadline. It proves mutation denial with recovery operations still available,
authenticated operational/doctor views, Argon2id/XChaCha20-Poly1305 secret backup, isolated
fresh-home identity/artifact/database verification, immutable audit export, status-0 clean drain,
complete archive export, task pause/resume fencing, explicit same-trust provider fallback through
the public doctor endpoint, status-2 forced evidence, and byte-identical forensic preservation.
Infrastructure tests cover atomic queue backpressure, durable concurrency dimensions,
deterministic jittered retry,
wrong-passphrase/tamper failure, unencrypted default backup, prior-schema snapshots, v10-to-v11
preservation, referenced-vs-orphan GC, configuration history, and forced-marker reconciliation.

`apps/mealyctl/tests/dashboard.rs` crosses both the CLI/dashboard HTTP boundary and a mock daemon
API boundary. It proves preflight and refresh use the six fixed authenticated operational
projections; the real daemon bearer never enters page, command, or JSON bytes; and the browser
capability contains 256 random bits. Missing capability, DNS-rebound Host, missing mutation Origin,
unknown DTO fields, invalid UUIDs, oversized bodies, unsupported methods, and arbitrary proxy paths
fail before daemon access. The accepted path proves canonical session/timeline responses and exact
forwarding of input idempotency keys, approval subject digests/decisions, and cancellation keys.
The snapshot's trailing-30-day usage projection preserves the exact requested bounds and validates
UTC bucket alignment/order, owner-terminal status balance, child-inclusive calls/tokens/cost, and
per-field plus aggregate JavaScript-safe integers. Store/API units independently prove exact
principal/binding isolation, child-lineage inclusion, the 31-day ceiling, and fail-closed terminal
reservations. Task-usage cases reject missing Origin, malformed IDs, widened DTOs, and values above the browser's
exact-integer ceiling; the accepted projection preserves distinct settled and reserved cost/token/
call fields and remains bearer-free. Unit evidence also rejects terminal reservations.
It also proves effect and attempt reads preserve exact route identity; cross-origin reads, invalid
IDs, empty evidence, and widened reconciliation DTOs fail locally; and one accepted reconciliation
forwards the exact linked IDs, inspected revision, outcome, non-empty evidence, and stable key while
never exposing the daemon bearer. No-store/CSP/frame restrictions are asserted. Focused unit tests
mutate exact Host, Origin, and capability independently and enforce the canonical 32 KiB evidence
bound. Schedule cases reject cross-origin reads, malformed or non-v7 creation identities,
out-of-range run limits, missing mutation Origin, unknown fields, unauthorized action prompts, and
revision overflow without daemon access. Accepted creation forwards the exact immutable
definition, reconciles an identical duplicate without a second mutation, and conflicts on
same-key semantic drift; detail/run reads validate canonical identity and occurrence shape, while
pause/resume/cancel forward only the rendered revision and require the exact status/revision +1
response. Governed-memory cases reject
missing Origin, malformed namespace/identity/search/limit/body fields, widened DTOs, and an
8 MiB-plus-one daemon response without disclosing its body. Accepted paths prove deterministic
bounded list/search/detail validation; content-digest and immutable revision/provenance validation;
adapter-derived stable proposal/correction source locators; duplicate proposal/correction
reconciliation without a second mutation; exact-revision owner-approved activation; and
revision-fenced pin/unpin/expire/reject/delete with scrubbed tombstones. The mock records every
daemon command and proves the bearer is absent from browser-facing bytes.
The ordinary CLI decoder shares the same streamed 8-MiB success/error ceiling; a unit regression
supplies oversized responses without relying on a truthful `Content-Length` and checks that neither
body is parsed or reflected. Further regressions require the exact API version on every successful
envelope, canonical bounded control-free fields on error envelopes, and terminal-safe JSON that
escapes bidi/C1 controls without changing its parsed value. The timeline client bounds a complete
SSE record before parsing, handles LF and split CRLF boundaries, requires an increasing cursor that
matches both the typed body and event name, and never prints raw daemon event bytes. Ordinary
requests now have a 30-second deadline, named long-running maintenance requests have a ten-minute
deadline, and the durable SSE path deliberately reconnects without a whole-stream timeout.
Connection tests additionally reject a symlinked descriptor, a symlinked home, group/world home
permissions, oversized sparse descriptors, and non-fixed-length bearer credentials. Native MCP
and direct-process inspection share a no-follow, identity-checked, preflight-bounded ELF reader;
extension manifest tests cover valid UTF-8, invalid UTF-8, sparse oversize, and symlink denial.
Extension cases reject missing Origin, malformed IDs, widened DTOs, manifest authority expansion,
stale or terminal state, and invalid projections. Accepted paths validate the complete data-only
manifest/history/grant, forward one exact enable grant, reconcile its identical duplicate without a
second command, disable and reconcile, re-enable from the new revision, and terminally revoke.
Unit evidence independently mutates mount access and secret-reference subsets.

`scripts/dashboard-smoke.sh` then builds both public binaries and crosses the complete real-process
chain: fresh schema-16 home, `mealyd`, dashboard preflight, browser capability extraction, bearer
non-disclosure, canonical effect/reconciliation not-found propagation plus mutation-Origin denial,
session creation, real UUIDv7-keyed dashboard schedule creation, identical replay, semantic-conflict
denial, exact dashboard definition/history reads, missing-Origin denial, pause, stale-revision
conflict, resume, terminal cancel, durable input
admission, empty governed-memory inspection, proposal plus duplicate reconciliation, explicit
activation, sensitivity-bounded search, pin/unpin, correction plus duplicate reconciliation,
expiry, content-scrubbing deletion, rejection, and deleted-tombstone listing, followed by live
active-task discovery, exact task cancellation, and the cancelled task's canonical usage/cost
evidence. The terminal dashboard refresh regression-proves that live doctor/readiness uses the
online schema path while an FTS-backed task is settling; deep integrity already passed before the
runtime reader pool opened. The post-settlement snapshot and `mealyctl usage --days 30` must both
include the terminal run with exact range/cost types and no bearer disclosure. A second real
session admits one digest-framed local Markdown attachment through `session send-file`; units
reject symlinks, unsupported extensions, invalid UTF-8/NUL, whitespace-drifted prompts, and
256-KiB-plus-one input,
plus any file below the private daemon home, and prove no host path enters the framed content. The
chat pseudo-terminal test additionally sends
`/attach` with a spaced path, observes the same path-free untrusted frame at the API, and proves the
prompt remains live while admission is in flight. It then builds a digest-pinned sample extension,
installs it inert through the CLI, verifies Origin-protected dashboard inventory/detail, performs
health-gated enable plus duplicate reconciliation, disable plus duplicate reconciliation,
re-enable, terminal revoke plus duplicate reconciliation, and clean bounded drain. CI and tag release jobs
run this Linux-local smoke after the workspace suite;
it requires standard ELF inspection utilities, `curl`, and `jq` but no network service or provider credential.

The tag matrix additionally runs `scripts/installed-package-smoke.sh` against the just-built,
checksum-matched installer and architecture-specific archive. Unlike the packaging fixture tests,
this starts only the installed
auditable binaries from an empty prefix/home, validates exact version/schema, the hardened systemd
user unit, and doctor evidence,
completes and recorded-replays a task, reports settled usage, creates and isolated-verifies an
online backup, drains cleanly, then uninstalls while proving `mealy.sqlite3` remains. Native tag
jobs additionally require enforceable observe and workspace-write sandbox
profiles from the installed daemon. This catches
release-payload or installer/runtime integration failures that source-tree smoke cannot.
The packaging fixture also modifies an installed threat model and proves slot verification blocks
an upgrade before either binary changes; `SECURITY.md` and the threat model are mandatory exact
payload inventory rather than unverified side documentation. A checksum-mismatched installer is
rejected before the installed-package smoke creates a prefix or home.
The public bootstrap fixture additionally proves the final user-journey boundary: a pseudo-terminal
fresh install automatically invokes the exact verified installed `mealyctl --home ... onboard`;
`--onboard` forces the same composition for an explicit caller and preserves separated
non-secret onboarding arguments exactly, while non-interactive and
`--no-onboard` installs print one exact handoff, `--check --onboard` is rejected before mutation,
and an existing home receives only `doctor` and `chat` handoffs. The independently installed
systemd smoke below exercises the real onboarding/service/health/doctor/first-turn transaction, so
the bootstrap test does not substitute a fake client for that behavior.
The Linux pseudo-terminal suite additionally invokes the real client with no subcommand. It
requires a clean home to display the onboarding route chooser without creating configuration,
requires a configured home to create and open a real durable chat, and proves non-terminal use
fails without mutation while naming the explicit automation commands.
The release builder also requires its explicit inventory to equal the complete regular-file-only
`docs/` tree. Archive and Debian install smokes verify that documentation indexes, requirements
coverage, testing guidance, decisions, research, benchmarks, and negative evidence survive the
package boundary; the Debian form mirrors the tree under `/usr/share/doc/mealy/docs`.

`packaging/test-deb-packaging.sh` independently constructs two Debian packages from identical
verified release payloads and requires byte-for-byte reproducibility. It checks the exact
`debian-binary`/control/data archive boundary, package identity and dependencies, absence of
maintainer scripts, root-installable modes, fixed command-link/binary identity, embedded payload and
Debian `md5sums`, checksum-identical third-party license documentation, explicit duplicate/tamper
failure, and checksum-manifest atomicity. The pinned license-notice generator independently runs
twice against the frozen all-feature supported-Linux dependency graph and rejects divergent,
active-content, path-leaking, missing, or oversized output. The tag matrix
then rejects every Lintian error or warning tag and runs `scripts/installed-deb-smoke.sh` on each
native package: it installs with `dpkg`, checks
root ownership and service generation, completes and recorded-replays a task, drains, removes the
package, and proves the user database remains. The archive smoke and Debian smoke use identical
binary bytes but exercise separate installation/removal boundaries.
For real ELF payloads, the Debian builder also compares each exact `NEEDED` set with the reviewed
x86_64/ARM64 glibc contract. A new native dependency fails packaging until its owning package and
the declared `Depends` field are updated deliberately.

Workspace configuration has two independent private-state overlap gates: the stopped-home CLI
rejects a root equal to, beneath, or containing the daemon home without changing configuration,
and startup rejects the same shapes plus redirected or unavailable roots from a manually changed
document. Extension enable and invocation apply the same rule to every host mount. The service
unit test and public configuration process test prove that workspace changes require a daemon
restart but no service regeneration, that the unit directly executes the exact configured daemon,
and that it does not wrap the daemon in a namespace that would disable per-tool Bubblewrap. The
same tests reject a volatile service home, assert a private umask and forced-drain restart
inhibition, and require a custom unit's activation command to link its exact safe path.
`scripts/systemd-service-smoke.sh` then starts the generated unit in the explicitly opted-in
GitHub-hosted runner or disposable container's user manager,
first drives full subscription-backed `onboard` through provider probing, default service
installation/start, authenticated health/doctor, the composed chat handoff, and one visible plus
searchable successful durable model turn with the expected provider/model status, context boundary,
and exact terminal token/cost/call accounting before leaving chat cleanly. The journey then
requires that the generated unit is enabled and running the exact installed daemon, restarts it
across a distinct main process, rechecks bounded health plus sandbox-conformant `doctor`, and
resumes the exact original durable session through `chat --continue` without creating a duplicate.
The pseudo-terminal client suite also renders two bounded recent-session choices, selects the
non-latest entry through `chat --pick`, verifies exact-session resume, and proves browsing creates
no session.
It removes that exact default unit and home before the existing independent service proof.
That proof requires both sandbox profiles to remain enforceable, resolves one exact approval, and requires
the effect itself—not merely its reporting task—to create the expected bytes before bounded drain.
It rejects both an outer Bubblewrap wrapper (which Ubuntu's reviewed profile makes incompatible
with nested per-tool namespaces) and systemd-user namespace directives that hardened Ubuntu cannot
apply before daemon exec. CI runs this process proof after the direct sandbox suite; both native tag
runners repeat it against the exact auditable release binaries and again from the root-owned paths
of the just-built Debian package.
Every user-manager command is time bounded. The failure trap removes only the exact link it created
before attempting bounded diagnostics/disable/reload calls, so an unavailable or pathologically
slow user manager cannot leave Mealy's temporary unit linked or hold a CI runner indefinitely. It
also retains the exact service main PID and directly terminates it only when both executable and
cgroup identity still match. Outside a detected container, the script refuses to touch any user
manager unless `MEALY_SYSTEMD_SMOKE_ALLOW_HOST=true` was set deliberately; the reviewed workflow
sets that opt-in only on the exact service-proof steps. The hosted CI step first removes that
variable and requires the guard to exit 73 with its exact refusal before running the opted-in proof.
An opted-in manager with more than 1,024 failed units is also refused before link or reload; the
script never clears unrelated diagnostic state on the operator's behalf.

`scripts/installed-update-rollback-smoke.sh` follows that clean user-manager proof with two real
managed archive slots. It packages and installs the already-built release binaries, creates a
durable successful turn and verified pre-update backup, then activates a checksum-valid synthetic
next patch whose daemon remains active but never becomes ready and whose client cannot service any
command. The private old helper must inspect manifests and every payload digest itself without
executing that candidate client, time out candidate qualification, stop it, exchange the verified
slots through the stable manager, restart and qualify the old service, and retire its helper copy.
The process gate requires a `rolled-back` durable transaction, exact old version/commit, green
health and `doctor`, searchable pre-update task, restorable backup, preserved home, and explicit
service cleanup. Remote GitHub acquisition/provenance is intentionally outside this failure
fixture and remains covered by the update trust tests and tag publication workflow.

Release binaries must be built through `scripts/build-release-binaries.sh`; `--auditable` is the
tag-workflow mode. The helper rejects inherited Rust flags, remaps account, Cargo, repository, and
relative source paths to stable virtual identities, then scans both executables for the exact host
paths. The release packager adds a platform-shaped user-home scan and its fixture deliberately
injects `/home/release-builder/private/source.rs` to prove rejection. For reproduction review,
build into two absolute target directories with distinct Cargo homes, compare both executables
byte-for-byte, scan printable strings for user-home paths, and run `cargo audit bin` on the exact
promoted binaries. The current auditable pairs are byte-identical across that same-host boundary;
the release process deliberately makes no cross-distribution linker reproducibility claim. The
x86-64 tag job additionally runs `scripts/fetch-release-soak-subject.sh` to promote the exact
external-soak daemon through a strict checked manifest, then applies binary audit, soak validation,
service, SBOM, package, attestation, and public-install tests to the promoted bytes. The fetcher's
mock-API regression proves success and rejects report-digest drift, a foreign uploader, and remote
asset-digest drift without network access.
The daemon unit regression also inspects and executes its dynamic-linker discovery command: the
program must be exact `/usr/bin/ldd`, arguments must begin with `--`, and the only explicitly
retained environment entry is deterministic `LC_ALL=C` after an environment clear. A release
process smoke launched with `PATH=/nonexistent` must still report the sandboxed fixture-write
runtime available and drain cleanly, proving ambient helper resolution is not required.

The provider-configuration process suite also covers the explicit OpenRouter path. A mock
authenticated `/models/user` catalog proves tool/text filtering, account-scoped bearer use,
context/output normalization, exact USD-per-token to integer-microunit conversion, unsupported
pricing-axis classification, output bounds, and zero configuration mutation. A separate streaming
activation proof verifies the beta Responses path, `store: false`, selected model/output bound,
credential isolation/brokering, and write-after-probe ordering.

The cross-phase recovery-load scenario at `apps/mealyd/tests/load_recovery.rs` admits 24 independent
sessions under an eight-worker/eight-provider concurrency ceiling, verifies exact idempotent
duplicates, kills all eight active provider attempts, checks SQLite integrity while stopped, and
restarts with new fences. Every task then succeeds with one tool call, interrupted attempts retain
their additional charged lineage, recorded-only replay performs zero live calls, and final
status/metrics prove no pending input, run, lease, approval, unknown effect, or failed delivery.
The scenario is also exercised in parallel process stress. Identical tool outputs deliberately
deduplicate to one blob: canonicalization retains the earliest verified blob-observation time and
does not infer an invalid cross-transaction ordering from independently sampled wall clocks. A
focused projection regression accepts shared-blob metadata with reversed timestamp samples while
continuing to reject negative times, redirected blob paths, digest drift, and ownership drift.
This is a bounded regression gate, not yet a published throughput benchmark or long soak.

The ignored public-process harness at `apps/mealyd/tests/soak.rs` is invoked through
`scripts/run-soak.sh`. It repeatedly advances several durable multi-turn sessions, injects exact
duplicates, kills the daemon only after a provider dispatch is recorded, and distinguishes
charged provider/read retries from undispatched model/read resumes. Every turn must succeed and
pass zero-live-call replay; every stopped/restarted database must pass `integrity_check`; final
status/metrics, clean drain, latency percentiles, RSS, and storage growth are emitted in a
versioned JSON report. An unsuccessful task first emits a bounded sibling
`REPORT.json.failure.json` containing the task, its post-admission timeline, and recorded replay;
connection metadata and the daemon bearer are never included. Report v2 also attributes SQLite
pages/payload/unused bytes to the largest
objects and counts context-manifest rows, inline bytes, artifact references, and source classes.
This prevents a large database from being mislabeled as one opaque regression. The runner defaults
to an optimized build and supports explicit round pacing for long durability runs. See
[`benchmarks/README.md`](benchmarks/README.md) and the checked
[2026-07-13 development baseline](benchmarks/2026-07-13-development-soak.json): 504 turns, eight
sessions, 12 hard restarts, p95 1.285 seconds, SQLite integrity `ok`, and zero residual work. The
baseline is not clean packaged-release evidence.

The retained-failure path exposed a one-second built-in fixture descriptor expiring after 1.153
seconds of host contention despite a five-second run limit. The fixture and passive-skill resource
descriptors now use that five-second ceiling, and storage accepts both historical and current skill
descriptors for recorded replay. The exact post-fix contention shape completed 2,376 turns across
eight sessions in 602.413 seconds while full Rust, packaging, clean-container, and real-browser
gates overlapped; it reported five hard restarts, 14 interrupted-provider recoveries, two read-tool
retries, complete replay, SQLite integrity `ok`, clean drain, and zero residual work. This is a
focused regression result, not a substitute for the fresh 24-hour durability gate.

Durable provider-request and validation-context JSON has a focused compatibility/corruption gate.
Objects below 4 KiB or without a size win stay as historical plain JSON. Larger objects may use the
`deflate-zlib-base64url-v1` envelope, but the durable SHA-256 remains the digest of the original
canonical object. Tests require legacy-row decoding, exact round-trip bytes, bounded decompression,
declared-length agreement, valid UTF-8/object JSON, digest verification at dispatch/replay, and
rejection of malformed or oversized envelopes. The public validation and Phase 2 process tests
then cross restart and zero-live-call replay using the same storage path.

`apps/mealyctl/tests/chat_pty.rs` runs the actual chat binary on a Linux pseudo-terminal against a
control endpoint that deliberately holds admission open. It proves the startup and refreshed
`/status` views use the authenticated provider/model and token limits, a subsequent prompt is
available while admission remains in flight, and `/quit` promptly aborts only local tracking. This
guards the concurrent REPL behavior at a real terminal boundary instead of only testing its parser.

Replay reports evidence as incomplete when an excluded artifact-backed context item cannot be
byte-for-byte reconstructed inside the SQLite-only verifier. The artifact adapter still verifies
the referenced blob, but Mealy does not claim a deterministic rendered digest or token estimate
without those bytes. This is a deliberate fail-closed boundary pending byte-aware replay evidence.

## Crash matrix

Each boundary is tested by a deterministic failpoint before and after the action:

| Flow | Failpoints |
|---|---|
| Input | before DB begin; after inbox insert; before commit; after commit before response |
| Lease | after claim; during heartbeat; after expiry; stale result commit |
| Model | before request; after request dispatch; after full response; before normalized commit |
| Effect | before authorization; after approval; before dispatch; after external mutation; before outcome commit |
| Artifact | during stream; after flush; after rename; before/after DB link |
| Outbox | before send; after remote accept; before delivery commit |
| Compaction | after source selection; after generation; before derived record commit |
| Migration | before backup; during migration; before version marker; exact-digest cross-schema activation; inherited stopped-home lock; atomic preserved-home exchange |
| Browser | before process; after CDP attach; during navigation; during proxy tunnel; before normalized commit; cancellation/deadline; runtime deletion before replay |
| Discord DM | after setup fence; before message reservation; after reservation; before cursor commit; saturated-page backfill; after 429; after remote accept; before outbox commit; hard restart/revocation |

## Security matrix

- Missing/invalid local API credential.
- Disallowed browser Origin and oversized body.
- Forged channel identity and replayed webhook.
- Discord DM wrong sender/channel/bot/webhook/system message, snowflake ambiguity, saturated-page
  gap, malicious mention text, nonce mismatch, rate-limit abuse, and ambiguous send acknowledgement.
- Cross-principal session/task/artifact/memory access.
- Model text pretending to approve an effect.
- Approval replay with changed arguments, tool version, target, policy, principal, or expiry.
- Sandbox path traversal, symlink, environment, process, and network escape attempts.
- Extension requests undeclared capability/secret/network target.
- MCP executable/tool/schema drift, malformed or excessive protocol output, ambient
  filesystem/environment/network/process access, and ignored cancellation.
- Browser bundle/product/protocol drift, personal-profile/host-CDP absence, unauthorized
  destination/method/auth/download/upgrade/direct-socket attempts, form/submit activation,
  excessive traffic/screenshot, startup/load timeout, and runtime-free replay.
- Secret canary search across provider payload, logs, journal, artifacts, and worker environment.

## Provider contract suite

Every provider adapter runs the same tests for:

- text and supported modalities;
- streaming and cancellation;
- tool-call normalization and malformed arguments;
- structured output;
- empty/partial responses and provider errors;
- exact protocol object/model identity and safe request identifiers;
- context overflow;
- usage and cost fields;
- retry hints and rate limits;
- cross-provider history projection;
- no credential leakage into normalized records.

Failure-contract cases additionally require fixed local classifications for provider error and
incomplete metadata; arbitrary upstream strings are not accepted as operator-facing error text.

The real-provider process suite also completes one endpoint call, hard-restarts the daemon, and
proves cumulative dispatch count and last-success time are reconstructed from canonical attempts
without a live redispatch. The new adapter still reports `configured_unprobed` until contacted,
which prevents historical success from weakening live routing health.

`crates/mealy-infrastructure/tests/web_live.rs` is an opt-in public-network check for the production
fetch adapter. It grants only `example.com`, performs a direct HTTPS fetch through DNS pinning and
peer verification, enforces a 32-KiB call bound, and checks sanitized text, exact URL citation,
media type, status, and raw-content digest. Run it separately because public DNS/network/site
availability cannot be deterministic CI evidence:

```sh
cargo test --locked --release -p mealy-infrastructure --all-features --test web_live \
  public_https_fetch_is_pinned_bounded_sanitized_and_cited -- --ignored --exact --nocapture
```

Deterministic unit coverage rejects named, literal, integer, hexadecimal, octal, IPv4-mapped, and
IPv6 loopback destinations; exercises all current IPv4 special-purpose ranges; and checks the
[IANA IPv6 allocation](https://www.iana.org/assignments/ipv6-unicast-address-assignments/)
and [special-purpose](https://www.iana.org/assignments/iana-ipv6-special-registry/) boundaries.
Unallocated `2000::/3` space fails closed until a reviewed release updates the dated table. The
content corpus distinguishes prefix-confusable tags such as `<scripture>`, respects quoted `>`
characters, removes comments and active blocks, fails closed on unclosed blocks, preserves word
boundaries, decodes bounded common/numeric entities once, and prevents cascading entity decoding.

The same test binary contains a separately filtered Brave Search check. It reads the credential
once from `BRAVE_SEARCH_API_KEY`, requests at most three results, and requires bounded HTTPS
citations without printing the credential:

```sh
BRAVE_SEARCH_API_KEY='...' cargo test -p mealy-infrastructure --all-features --test web_live \
  live_brave_search_is_credential_scoped_bounded_and_cited -- --ignored --exact --nocapture
```

The manual `mealy-live-provider-smoke` GitHub workflow provides the corresponding account-scoped
release gate. Its default `openrouter-free` path discovers the account-visible catalog and selects
only a tool-capable exact `:free` model with complete token limits, exact zero input/output prices,
and no unsupported pricing axes. Its optional exact model input can only narrow that eligible set;
it cannot bypass any free-route check. Direct HTTP adapters reserve 2,048 additional normalized
input tokens for provider-side framing, tool schemas, and tokenizer variance. Direct OpenAI or
Anthropic runs instead require current model/limit/price inputs and the selected
`live-provider-smoke` GitHub Environment secret. The
`private-responses` choice fixes the destination to
`https://the-beast.taile6fad0.ts.net/v1`, requires an exact model and verified context limit, and
forces zero prices; neither a dispatch input nor a pull request can redirect `LOCAL_API_KEY`. It performs the real setup
probe and a complete durable
workspace-read tool turn with an exact citation, asserts provider health, settlement, usage,
recorded-only replay, sandbox conformance, clean
drain, and absence of the credential from config/log/JSON output. Brave Search is an independent
opt-in checkbox. The workflow is `workflow_dispatch` only, never runs on untrusted pull requests,
and has read-only repository permission. The `live-provider-smoke` Environment requires an
explicit repository-owner review; add a credential only when its reviewed run is ready. The job
resolves exactly one of its secrets
`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY`, or `LOCAL_API_KEY` from the selected adapter; unused
provider secrets are never added to the step environment. The gate binds terminal polling to the
exact durable `task.created` event after the admission cursor rather than relying on transcript
search. It observes the atomic promotion's `input.promoted` and `task.created` events in order,
allows at most five minutes for a congested free model to settle, and prints only a
credential-free task/usage and durable run-failure summary when that bounded terminal contract
fails. The default 30-second provider-call budget admits the 30-second routing estimate written by
every guided provider setup.
The job has a 20-minute hard timeout and a single non-cancelling concurrency group so two reviewed
manual probes cannot overlap or terminate each other midway through settlement.
Its workflow-controlled run name contains the selected provider and exact SHA. The release's
checked selector requires a successful manual `openrouter-free` identity from the canonical
workflow and repository URL; regression fixtures prove a private provider, stale SHA, failure,
incomplete run, wrong event/path/name, spoofed title, foreign URL, and malformed API response are
all rejected.
The protected CI workflow similarly records its event and SHA in a workflow-controlled run name.
Its release selector accepts only a successful `push` run for the exact commit on `main` from the
canonical CI workflow and repository URL; fixtures reject pull-request-only, stale, wrong-branch,
failed/incomplete, wrong-event/path/name/title, foreign-URL, and malformed responses.

## Validation gates

CI initially runs:

```text
cargo fmt --all -- --check
actionlint v1.7.12 (release archive SHA-256 pinned in the workflow)
zizmor v1.28.0 offline auditor profile (release archive size/SHA-256 pinned)
cargo-deny v0.20.2 advisories/licenses/bans/sources policy (release SHA-256 pinned)
embedded dashboard JavaScript syntax validation
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets --all-features
cargo test --locked --workspace --doc --all-features
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --all-features --no-deps
scripts/validate-documentation.py --cli target/debug/mealyctl
real-daemon dashboard smoke, RustSec audit, Bash syntax plus ShellCheck, and packaging lifecycle
```

The checked-in CI matrix compiles both production control-plane targets on Linux x86-64/ARM64,
runs clean native package builds on Ubuntu 24.04/26.04, Debian 13, and Fedora 44 for both
architectures plus Arch Linux on x86-64, and runs the strict/sandbox/browser Linux gates on the
explicit Ubuntu 24.04 image. It semantically validates all workflow files with pinned `actionlint`, scans them
offline for unsafe triggers, permissions, secret handling, interpolation, and credential persistence
with pinned `zizmor`, and has separate Bubblewrap, generated-systemd-service, and pinned-browser
conformance lanes. The service lane checks an actual approved mutation because a startup probe
alone cannot prove that the outer syscall policy permits secure file creation. `doctor` explicitly
denies every profile whose guarantees the current host cannot supply. Live-provider tests are
opt-in and cannot be the sole evidence for deterministic behavior.
The documentation validator uses the built CLI and registered API router as authorities. It rejects
undocumented or stale HTTP method/path pairs, public top-level commands absent from the usage set,
missing/empty core documents, broken local Markdown paths or fragments, symlink substitutions, and
links that escape the repository. Its separately regression-tested package mode enumerates a
bounded filesystem tree without relying on `.git`; every native build and public-download job runs
that mode against the extracted archive and its exact packaged `mealyctl`. This prevents a complete
source checkout from masking omitted, broken, duplicated, or stale documentation in distributable
bytes. Remote links remain an operator-review concern so an unrelated network outage cannot make
protected CI nondeterministic.
The strict gate also runs `scripts/test-release-notes.sh`. Its synthetic valid report must render
byte-identically twice, while tag/version drift, a foreign workflow URL, a short or dirty soak,
incomplete turns, corrupt SQLite, and residual work must all fail. The tag publisher uses that same
renderer to bind the exact commit, approved live-provider run, release workflow, daemon digest,
and checked soak measurements into the immutable release notes.
`scripts/test-public-license-validator.sh` separately accepts synthetic Apache-2.0, MIT, and dual
MIT/Apache workspaces with either matching SPDX metadata or the existing exact `LICENSE`-file
inheritance, while rejecting restrictive terms, redirected/mismatched metadata, an unsupported
expression, and a member package that does not inherit the workspace license. The tag workflow
runs the validator on the real checkout; the copyright-holder-selected canonical Apache-2.0 text
and existing exact license-file inheritance now pass that public-use gate.
The current tree additionally passed the equivalent GCC cross-check for
`aarch64-unknown-linux-gnu`; ARM64 Linux runtime/package evidence remains the native CI and tag
matrix's responsibility. macOS and Windows are outside the active support and CI contract.
Every workflow job has an explicit scope-appropriate timeout instead of inheriting GitHub's loose
default.

Run a bounded optimized soak separately from the default CI wall-clock budget:

```text
scripts/run-soak.sh --release --duration-seconds 300 --sessions 8 \
  --restart-every-rounds 10 --provider-delay-ms 250
```

For release-artifact durability evidence, pass an already verified extracted package daemon with
`--mealyd /absolute/path/to/bin/mealyd` and a new disk-backed directory with
`--home /absolute/path/to/new-soak-home`. The harness checks the daemon version, launches that
exact file for every restart, and records its SHA-256 plus `external_release_binary` mode in both
success and retained-failure reports. The explicit home must not exist, is rejected on tmpfs or
ramfs, records its filesystem type, and is retained for post-run SQLite/forensic inspection.
Without these options, the report honestly identifies Cargo's integration binary and a temporary
home instead.

## Requirements coverage

Scenario names and the release review in [`REQUIREMENTS_COVERAGE.md`](REQUIREMENTS_COVERAGE.md) map
MUST requirement groups to concrete storage, API, process, property, migration, and security tests.

Green tests prove only covered requirements. Completion reviews inspect the mapping instead of treating `cargo test` as proof of the entire product.
