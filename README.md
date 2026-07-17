# Mealy

Mealy is a local-first, self-contained agent runtime for a reliable personal AI assistant.

## Run it

For a published stable Linux release, install GitHub CLI plus the host prerequisites in the
[quickstart](docs/QUICKSTART.md), then download and verify the small release
bootstrap before running it. The bootstrap selects x86-64 or ARM64, resolves one exact stable tag,
verifies every downloaded asset against the tag's release-workflow attestations and checksums, and
installs rootlessly beneath `$HOME/.local` without a Rust toolchain, root access, or GitHub account:

```sh
tmp=$(mktemp -d)
curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --output "$tmp/install-mealy-release.sh" \
  https://github.com/Amekn/project_mealy/releases/latest/download/install-mealy-release.sh
curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --output "$tmp/ATTESTATION-installers.sigstore.json" \
  https://github.com/Amekn/project_mealy/releases/latest/download/ATTESTATION-installers.sigstore.json
gh attestation verify "$tmp/install-mealy-release.sh" \
  --repo Amekn/project_mealy \
  --signer-workflow Amekn/project_mealy/.github/workflows/release.yml \
  --bundle "$tmp/ATTESTATION-installers.sigstore.json" \
  --deny-self-hosted-runners
chmod 0755 "$tmp/install-mealy-release.sh"
"$tmp/install-mealy-release.sh"
```

The command prints the exact `setup` and service-install handoff. No release is implied when the
repository has not published and attested these assets.

Published tags also retain attested native macOS ARM64 and Intel preview archives. They support
provider setup, conversation, inspection, backup, and a LaunchAgent, but intentionally deny
worker/tool sandbox profiles and are not production worker targets. See the
[macOS preview instructions](docs/QUICKSTART.md#macos-conversation-only-preview) for the exact
download, provenance verification, checksum, and owner-local install commands.

To build this checkout instead, run:

```sh
scripts/build-release-binaries.sh
```

For a real model, run `target/release/mealyctl --home "$HOME/.mealy" setup` while the daemon is
stopped; the wizard supports API-key-backed OpenAI, Anthropic, OpenRouter, or a literal-loopback
Responses-compatible model and prints the exact next commands. Advanced stopped-home commands
also support authenticated private Responses endpoints and owner-local OpenAI/Claude subscription
sign-in through the official Codex or Claude client. For an immediate offline conformance run,
skip setup and use the deterministic fixture provider.

Start the daemon in terminal 1 and chat in terminal 2:

```sh
# terminal 1
target/release/mealyd --home "$HOME/.mealy"

# terminal 2
target/release/mealyctl --home "$HOME/.mealy" doctor
target/release/mealyctl --home "$HOME/.mealy" chat
```

At the `you>` prompt, plain text queues a turn and `/help` lists steering, approvals, memory,
governed tools, and `/attach PATH`. For a persistent user service after installing both binaries
side by side, run `mealyctl --home "$HOME/.mealy" service install` and execute the printed
activation command. See the [quickstart](docs/QUICKSTART.md) for provider setup and capabilities,
or the [release guide](docs/RELEASE.md) for attested archive and Debian-package
install/upgrade/rollback behavior. Treat a build as published only when its exact tag workflow has
produced the documented assets and attestations; never mistake a local dirty build for an attested
package.

> **Implementation status (not yet a public production release):** the durable release-one runtime
> proof is complete, and Mealy now supports
> bounded conversation through independently implemented `OpenAI` Responses and Anthropic
> Messages adapters, including explicit mixed-protocol fallback chains, plus a guarded OpenRouter
> stateless Responses-beta preset with account-filtered catalog/price discovery. A clean-home
> `mealyctl setup` wizard reviews non-secret provider/model/limit/price inputs,
> consumes credentials only from standard environment variables, performs the existing bounded
> activation probe, brokers the key, and prints exact daemon/doctor/chat handoff commands. A
> separate official-client bridge supports existing ChatGPT and Claude subscription sessions
> without importing OAuth tokens: it pins the canonical client executable and SHA-256, clears API
> key variables, disables client tools/connectors/session persistence, validates structured output
> and usage, and fails activation when the official client is not signed in. ChatGPT subscriptions
> are not OpenAI API keys, and these owner-local bridges are not the unattended release-acceptance
> provider path. A
> concurrent first-party chat REPL provides durable queue/steer/interrupt controls, bounded
> owner-selected local UTF-8 text-file admission, model/tool
> progress, and exact-subject approval commands. On Linux, real-provider runs can use bounded,
> cited list/stat/read/search tools over explicitly granted workspaces; explicitly activated profiles can also use
> bounded, cited web search/fetch. Owner-reviewed native MCP stdio servers can expose selected,
> schema-pinned read-only tools through a fresh no-network Bubblewrap session per call. Explicit
> Linux x86_64 profiles can additionally enable a content-pinned Chrome Headless Shell
> `browser.snapshot` tool: each call uses a fresh agent-only profile and private network namespace,
> renders bounded accessibility evidence, can either follow one exact accessible GET link or
> activate one exact form-free `<button type="button">`, or fill one exact non-password
> text/search control and optionally construct a same-origin GET containing only that named field.
> It can also capture one exact accessible same-origin attachment up to 512 KiB into durable
> digest/base64 evidence, and can return a bounded PNG without
> exposing CDP or a personal browser profile. Browser traffic is narrowed to
> the initial exact origin, so cross-origin redirects, subresources, and links fail closed. Explicit
> `/act` turns can also create one new file in a
> separately writable workspace after exact approval and sandboxed dispatch; `/edit` can atomically
> replace one existing bounded file only while its approved current-content digest still matches,
> using either complete new content or up to 16 ordered exact-text replacements whose expected
> non-overlapping occurrence counts also match. Explicit `/manage` turns can create one directory
> beneath an existing parent, move one digest-matched bounded regular file to an absent path,
> remove one digest-matched bounded regular file, or remove one empty directory. These lifecycle
> operations never overwrite, recurse, follow symlinks, or create missing parents.
> Explicit `/run` turns can run one owner-configured, digest-pinned installed executable directly inside one
> writable workspace with exact argv approval and no ambient network, secrets, environment, or
> other configured command. A guided, one-time-code Telegram Bot API pairing flow provides exact
> sender/chat allowlisting, durable polling/deduplication, bounded text attachments, queue/steer/interrupt,
> progress/final messages, exact-subject approvals, restart recovery, and terminal revocation.
> A separate least-authority Discord adapter binds one explicit human-to-bot DM, uses REST-only
> bounded lossless history polling, decimal-string snowflake cursors, platform `Retry-After`,
> mention-free nonce-deduplicated delivery, the same controls/approvals, restart recovery, and
> terminal revocation. Durable five-field cron schedules can feed local, Telegram, or Discord
> sessions with explicit timezone,
> downtime, overlap, pause/resume, and run-history semantics. A temporary `mealyctl dashboard`
> serves a CSP-hardened loopback console for durable conversation input, live timelines,
> digest-bound approval decisions, cooperative task cancellation, exact 30-day terminal-run
> aggregates plus per-task settled/reserved token/call/cost evidence, exact effect/attempt inspection,
> evidence-bound unknown-outcome reconciliation, retry-safe keyed schedule creation, exact
> schedule/run-history inspection, and revision-fenced schedule pause/resume/cancel. It also
> provides governed-memory namespace/search,
> exact revision/provenance review, proposal, explicit activation, correction, pin/unpin,
> expiry/rejection, and content-scrubbing deletion. A manifest-derived extension view exposes
> bounded inventory/detail and exact-grant enable, disable, and terminal revoke with safe duplicate
> reconciliation; install/stage/invoke remain CLI-only. These controls sit alongside operational status without
> exposing the daemon bearer to the browser or providing an arbitrary proxy. It is not yet a
> production general-purpose assistant: recursive tree mutation, directory moves, overwrite/chmod,
> interactive
> arbitrary browser events/clicking, POST forms, uploads, unbounded/owner-path downloads,
> persistent or personal profiles,
> HTTP or credential-bearing MCP,
> verified provider-wide price coverage, owner-reviewed live-provider acceptance, and published
> clean-host release evidence remain in progress. The checked clean 24-hour packaged-binary report
> is complete. Credential-scoped live model discovery is available
> for both supported provider protocols, alongside a credentialless, literal-loopback
> Responses-compatible discovery/activation preset. See the
> [quickstart](docs/QUICKSTART.md) for exactly what can be run today.

This repository now contains the completed **Phases 0–7 release-one runtime proof**: a runnable local daemon,
authenticated CLI/API, durable session inbox, FIFO/steering/interruption semantics, fenced work
leases, restart recovery, outbox delivery, resumable timeline SSE, and a bounded provider-neutral
agent loop. Its default offline conformance profile uses a deterministic local provider and one
fixture read tool; configured production profiles use the external adapters described below. The
loop persists immutable context manifests, normalized attempts and usage, content-addressed
artifacts, cancellation, checkpoints, and recorded-only replay. Its approval-gated fixture write
uses an exact policy subject, durable effect ledger, stable idempotency key, out-of-process Linux
sandbox, explicit unknown-outcome reconciliation, automatic expiry, and effect-aware replay.
Every admitted task also has explicit success criteria and risk policy. Low-risk reads retain
deterministic validation evidence; medium-risk writes cannot succeed until a fresh, read-only
validator run passes. External-provider assistants can call `agent.delegate` to create one durable,
isolated child work package. The launch parks the parent atomically; the child inherits only the
parent's configured read tools, receives a separately capped budget with delegation depth zero,
and returns a fenced `delegation://result` before the parent resumes. Parent cancellation propagates
to queued or running children, both root and child recorded-only replay are verified, and owners can
inspect exact child authority, budget, lineage, state, and result through the API or `mealyctl
delegation` commands. Lower-level delegation contracts continue to intersect
parent/request/policy capabilities and arbitrate exclusive resource claims.
Governed memory now has proposal, explicit activation/rejection, immutable correction history,
pin/expiry/deletion, owner-scoped export, and filtered FTS5 retrieval with a deterministic degraded
fallback. A one-command owner-approved `memory remember` flow and chat-native remember/search/
inspect/correct/lifecycle controls generate exact content provenance and retain recoverable proposal
IDs after partial activation. Literal cross-session transcript search returns digest-linked bounded
excerpts and is scoped to the exact principal/channel binding before matching. The assistant may
suggest an exact non-sensitive `/remember` command but cannot activate or claim memory state.
Session compactions are immutable artifacts whose typed goals, safety constraints,
approvals, effects, and source-event digests are validated against canonical history. Retrieved
memory is labeled untrusted evidence, compaction and memory provenance are owner-inspectable, and
recorded replay survives content deletion and daemon restart. Separate Responses and Anthropic
Messages adapters now provide secret-safe bounded conversation and streaming, definite-failure
retry/backoff, mixed-protocol trust-preserving fallback, independent health, exact durable usage/
cost settlement, active cancellation, and effect-free replay. Linux workspace grants add
race-resistant `openat2`-confined list/stat/read/search tools with
logical citations, explicit stopped-daemon grant/revoke, context-epoch rotation, and recorded-only
replay. Configured web tools add brokered Brave Search and DNS-pinned, SSRF-hardened text fetches
with immutable network ceilings and cited replay. A production `workspace.create_file` action adds
separate writable-root ceilings, explicit action-mode admission, exact logical-target approval,
create-new semantics, fresh validation, one-shot Bubblewrap execution, and zero-dispatch replay.
The companion `workspace.replace_file` action adds a separate `/edit` intent boundary, an exact
approved SHA-256 precondition over the existing regular file, and either bounded complete content
or at most 16 ordered exact old/new-text replacements with approval-bound occurrence counts. The
same worker performs an atomic rename plus directory synchronization; digest, occurrence-count,
size, UTF-8, stale, and symlink failures leave the original unchanged. Public-process evidence
crosses model proposal, exact approval, sandbox execution, fresh validation, and recorded-only
replay for the structured-patch path.
The separate `workspace.manage_path` action adds an explicit `/manage` intent boundary for one
approval-bound path lifecycle operation: create an absent directory, move a digest-matched regular
file without overwrite, remove a digest-matched bounded regular file through exclusive quarantine,
or remove an empty directory. Linux `openat2`/`renameat2`/`unlinkat` confinement rejects traversal,
symlinks, mount crossing, stale content, missing parents, collisions, non-regular files, and
non-empty directories. The mixed operation is conservatively non-idempotent with reconcile-only
crash recovery; public-process evidence covers proposal, exact two-path move approval, sandbox
execution, fresh validation, and execution-free replay.
Local MCP stdio integration implements the exact `2025-11-25` lifecycle and newline-delimited
JSON-RPC transport. Inspection executes without granting authority; activation copies a native ELF
server into owner-private content-addressed storage and pins its bytes, direct arguments, complete
paginated tool set, each selected full definition, schemas, timeout, and output bound. Startup and
every call re-discover the complete tool set and fail closed on executable, schema, definition, or
extra-tool drift. Each fresh session receives an empty environment, private `/tmp`, no network,
home, workspace, secret, shell, `PATH`, or child-process authority, plus hard resource limits.
Calls are cancellable, cited as `mcp://SERVER/TOOL`, durable, and recorded-only replayable after the
executable is unavailable. Complete backups and migration rollback preserve and re-verify every
configured server. This first boundary deliberately excludes scripts/interpreters, HTTP MCP,
server secrets, host workspace mounts, and effectful MCP tools.
The initial rendered-browser adapter similarly treats Chrome as untrusted runtime code. The complete
Headless Shell bundle and CDP product are pinned, owner-installed, and re-verified; Bubblewrap gives
each invocation an empty environment, ephemeral profile, private network namespace, and no
home/workspace/secret access. A Unix-socket policy proxy re-resolves and pins the same owner-granted
web destinations as `web.fetch`, admits only GET/HEAD navigation traffic, and bounds connections,
bytes, and time. CDP blocks non-read requests, authentication, ambient downloads,
WebSocket/WebTransport,
and direct sockets. An exact textbox/searchbox fill uses a native value setter captured before page
code and dispatches no input/change event; optional submission is rebuilt in Rust as one same-origin
GET containing only the selected named control, excluding hidden or sibling fields. Results contain
only normalized accessibility text/elements, final URL/title, fill/activation evidence, and an
optional 512-KiB PNG. One explicit exact-link download temporarily uses a GUID-named ephemeral
directory, `NOFOLLOW` reads, and a 512-KiB cap to emit digest/base64 evidence without writing an
owner path. Complete backup and migration rollback preserve the content-addressed
bundle; recorded replay does not launch Chrome.
The high-risk `process.run` action adds stopped-daemon command grant/revoke, root-controlled path
and byte pinning, explicit `/run` admission, exact command/workspace/argv approval, direct execution
without shell or `PATH` mediation, per-attempt single-command mounting, bounded resources, no
network/secrets/environment, never-retry recovery, fresh validation, and recorded-only replay.
Recursive removal/creation, directory moves, overwriting moves, chmod, and effectful/arbitrary browser
interaction remain future work. Digest-pinned data-only extension manifests now drive
explicit owner grants and one-shot Bubblewrap RPC workers; install, health-gated enable, invocation,
upgrade, disable, crash isolation, and terminal revocation retain durable evidence. A separate
data-only skill lifecycle verifies exact package inventory and asset digests, publishes immutable
owner-private revisions, stages install/update disabled, and activates only an owner-reviewed
manifest digest. Enabled instructions rotate context provenance; passive resources remain unloaded
until a bounded cited `skill.read_resource` call, and manifest tool requirements never grant
authority. Skill packages are covered by complete backup/restore and cross-schema rollback. A built-in
signed webhook channel maps a verified external subject to a dedicated session, authenticates the
exact raw body with brokered HMAC keys, rejects stale/replayed deliveries, and signs retrying
outbound callbacks from the durable outbox. The first-party Telegram adapter verifies its bot with
`getMe`, uses a high-entropy expiring private-chat challenge to discover the owner safely, brokers
the token outside SQLite/configuration, binds one exact sender and chat to a
dedicated session, durably reserves each update before effect, advances the Bot API cursor only
with terminal evidence, recovers after hard restart, and routes bounded progress, final, and
approval notifications through the same outbox. Definite send failures retry; ambiguous sends are
terminally parked to prevent duplicate messages.
The Discord DM adapter independently verifies `GET /users/@me`, channel type `1`, and exactly one
non-bot recipient before creating a dedicated session. It stores snowflakes as canonical unsigned
decimal strings, establishes a post-setup floor, reserves every message before effect, and walks
saturated newest-first history backward before advancing the durable cursor so a 100-message page
cannot silently skip a gap. Only exact-author default text messages are admitted; attachments,
webhooks, system messages, other users, channels, and bot output are durably ignored. Outbound
messages cap at 2,000 characters, suppress all mentions and embeds, and use a stable 25-character
nonce with `enforce_nonce`; 429 responses honor the platform delay, while ambiguous transport,
server, or acknowledgement outcomes are terminally parked rather than duplicated.
Recurring schedules are canonical SQLite state with IANA time zones, bounded coalesced misfire
handling, same-schedule overlap policy, leased occurrence claims, deterministic session admission,
UUIDv7-keyed duplicate-safe creation, revision-fenced pause/resume/cancel, and durable run history.
Scheduled action-mode prompts require
an explicit creation-time opt-in and still traverse their normal exact approval boundary.
Operational hardening adds schema-versioned configuration and rollback history, durable daemon
lifetime evidence, safe mode, bounded clean/forced drain, authenticated status/metrics/doctor
views, immutable online backups, optional authenticated-encrypted secret archives, isolated fresh-
home restore verification, scoped exports, retention/GC, automatic pre-migration snapshots with
exact-digest atomic cross-schema activation,
corrupt-database forensic preservation, owner-level service installation, request traces, and
explicit platform sandbox conformance reporting.

Ordinary resumed sessions project a chronological suffix of successful user/assistant turns into
both provider protocols: at most 32 prior turns and 512 KiB are discovered before the per-attempt
token compiler applies its recorded budget decisions. The latest authenticated input is mandatory
and cannot be silently displaced by history. A cited compaction cuts off the raw turns it replaces,
and context-epoch rotation excludes prior-session-derived material so a revoked workspace or tool
identity cannot return through old assistant text. The exact projection remains recorded-replay
verifiable.

## Start here

- [`REQUIREMENTS.md`](REQUIREMENTS.md) — normative requirements and release-one acceptance boundary.
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — practical design and requirement traceability.
- [`docs/research/REFERENCE_SYSTEMS.md`](docs/research/REFERENCE_SYSTEMS.md) — pinned review of all eight reference systems.
- [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md) — vertical phases and exit gates.
- [`docs/QUICKSTART.md`](docs/QUICKSTART.md) — prerequisites, release build, first run, and current limitations.
- [`docs/PRODUCTION_READINESS.md`](docs/PRODUCTION_READINESS.md) — active blockers and competitive acceptance gates.
- [`docs/OPERATIONS.md`](docs/OPERATIONS.md) — installation, backup, retention, and recovery runbook.
- [`docs/RELEASE.md`](docs/RELEASE.md) — attested package install, upgrade, rollback, and maintainer checklist.
- [`docs/REQUIREMENTS_COVERAGE.md`](docs/REQUIREMENTS_COVERAGE.md) — normative release evidence.
- [`docs/benchmarks/`](docs/benchmarks/) — bounded soak measurements and reproduction commands.
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — trust boundaries and abuse cases.

## Repository map

- `apps/mealyd`: trusted daemon composition root.
- `apps/mealyctl`: local client and administration CLI.
- `crates/mealy-domain`: pure IDs and lifecycle state machines.
- `crates/mealy-application`: use cases, recovery planning, and ports.
- `crates/mealy-infrastructure`: SQLite, artifacts, processes, providers, and OS adapters.
- `crates/mealy-protocol`: versioned transport DTOs.
- `crates/mealy-api`: authenticated HTTP/SSE adapter.
- `crates/mealy-testkit`: deterministic scenario support.
- `docs`: design, decisions, research, and verification strategy.
- `schemas`: reviewed external contract fixtures.
- `tests`: integration and public-API scenarios.

## Development

The workspace is pinned by `rust-toolchain.toml`.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo test --workspace --doc --all-features
```

Run the daemon in one terminal:

```sh
cargo run -p mealyd -- --home .mealy
```

Then drive its authenticated loopback API through the CLI:

```sh
cargo run -p mealyctl -- --home .mealy health
cargo run -p mealyctl -- --home .mealy status
cargo run -p mealyctl -- --home .mealy doctor
cargo run -p mealyctl -- --home .mealy chat
# At the `you>` prompt: /attach ./owner selected notes.md
cargo run -p mealyctl -- --home .mealy session create
cargo run -p mealyctl -- --home .mealy session send <SESSION_ID> "hello"
cargo run -p mealyctl -- --home .mealy session send-file <SESSION_ID> ./notes.md \
  --prompt "Summarize this untrusted document."
cargo run -p mealyctl -- --home .mealy session status <SESSION_ID>
cargo run -p mealyctl -- --home .mealy session watch <SESSION_ID>
cargo run -p mealyctl -- --home .mealy task status <TASK_ID>
cargo run -p mealyctl -- --home .mealy task pause <TASK_ID> --expected-revision <REVISION>
cargo run -p mealyctl -- --home .mealy task resume <TASK_ID> --expected-revision <REVISION>
cargo run -p mealyctl -- --home .mealy task replay <TASK_ID>
cargo run -p mealyctl -- --home .mealy task cancel <TASK_ID> "stop this run"
cargo run -p mealyctl -- --home .mealy delegation list --limit 20
cargo run -p mealyctl -- --home .mealy delegation status <DELEGATION_ID>
cargo run -p mealyctl -- --home .mealy approval list
cargo run -p mealyctl -- --home .mealy effect status <EFFECT_ID>
cargo run -p mealyctl -- --home .mealy memory list --workspace <WORKSPACE_IDENTITY>
cargo run -p mealyctl -- --home .mealy memory search --workspace <WORKSPACE_IDENTITY> "release"
cargo run -p mealyctl -- --home .mealy compaction status <COMPACTION_ID>
cargo run -p mealyctl -- --home .mealy extension list
cargo run -p mealyctl -- --home .mealy skill list
cargo run -p mealyctl -- --home .mealy channel list
cargo run -p mealyctl -- --home .mealy channel telegram-pair
cargo run -p mealyctl -- --home .mealy channel telegram-list
cargo run -p mealyctl -- --home .mealy channel discord-pair --channel-id <DM_CHANNEL_ID>
cargo run -p mealyctl -- --home .mealy channel discord-list
cargo run -p mealyctl -- --home .mealy schedule create <SESSION_ID> --name "weekday brief" --cron "0 9 * * MON-FRI" --timezone Pacific/Auckland "Prepare my weekday brief."
cargo run -p mealyctl -- --home .mealy schedule list
cargo run -p mealyctl -- --home .mealy backup nightly
cargo run -p mealyctl -- --home .mealy restore-verify nightly
cargo run -p mealyctl -- --home .mealy restore-activate nightly-secret --expected-manifest-digest <SHA256> --approve
cargo run -p mealyctl -- --home .mealy export audit-snapshot audit
cargo run -p mealyctl -- --home .mealy export complete-snapshot complete
cargo run -p mealyctl -- --home .mealy drain
```

`mealyd` creates an owner-only home and bearer credential, binds only to a literal loopback IP,
recovers before publishing readiness, and prevents two daemons from owning one home. `mealyctl`
disables proxies and redirects, validates the private loopback descriptor, prints generated
idempotency keys before dispatch, retries admission with the same key, and reconnects timeline
watchers after daemon restart without losing their durable cursor.

The process scenarios hard-kill the daemon across admission, provider, read-tool, approval, effect
preparation, external mutation, outcome, and observation boundaries; restart from the same
database; and verify fencing, exact budget settlement, explicit reconciliation, effect-free
replay, and continuous timeline evidence. Replay also fails closed for corrupted graph, journal,
sequence, checkpoint, descriptor, artifact, usage, deadline, timeline, memory, compaction,
extension, webhook, Telegram, and channel evidence. The Telegram public-process proof covers live
bot verification, exact allowlists, text attachment bounds, retry, cursor recovery, remote
schedule admission, restart deduplication, and token-destroying revocation. Phase 7 process tests
additionally prove safe-mode mutation
denial, encrypted backup and isolated restore verification, immutable export, clean and forced
drain, pre-migration preservation, and corrupt-database forensics. See
[`docs/OPERATIONS.md`](docs/OPERATIONS.md) for operator workflows and downgrade constraints.

## Reference clones

The eight research repositories are shallow-cloned outside this worktree at:

```text
../mealy-agentic-references/
```

Their commit pins and licenses are recorded in the research report. They are not build dependencies. The Claude Code mirror has no license and must not be used as a code source.

## License

See [`LICENSE`](LICENSE).
