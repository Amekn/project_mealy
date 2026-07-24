# mealyctl

Local client for the versioned API. Normal commands never open SQLite or mutate daemon files
directly. Explicit offline owner workflows cover user-service installation, atomic verified backup
activation, and approved provider, fallback, workspace read/write, installed direct-command, web,
rendered-browser, native MCP stdio, data-only skill, and digest-pinned rollback configuration while the daemon lock
is free.

`mealyctl --home "$HOME/.mealy" setup` is the clean-home first-run path. It interactively selects
`OpenAI`, Anthropic, `OpenRouter`, or a credentialless literal-loopback provider; prompts only for
non-secret model/limit/price inputs; imports a remote key from the provider's standard environment
variable; reviews an exact config digest; and requires typing `APPROVE`. It reuses the normal
bounded activation probe and conflict-safe broker, emits provider JSON on stdout for automation,
and prints exact daemon/doctor/chat handoff commands on stderr. Supplying all flags plus `--approve`
provides the same process-tested non-interactive path. `--skip-connectivity-test` is explicitly
staged and does not count as production verification.

Owner-local subscription activation is deliberately separate from API-key handling. The ordinary
`onboard --route chatgpt-subscription` path uses the official Codex app-server to read only coarse
account state, obtain a browser or device-code challenge after separate terminal consent, and
select the current account-catalog default model. It never reads or stores email, account IDs,
OAuth/session tokens, or a broker identity. The lower-level
`config provider-subscription-openai` command assumes Codex is already signed in and retains its
`gpt-5.6`/128,000-token defaults for explicit stopped-home automation. Both paths allow deliberate
model/context overrides; onboarding accepts only an exact account-catalog model. The runtime bridge
canonicalizes and SHA-256-pins the selected executable, excludes provider API-key variables and
host-client tools/connectors, and runs a bounded structured connectivity probe. Activation raises the configured
provider deadline only as far as its declared latency estimate and total run wall-time permit;
official-client input overhead is included in the durable token reservation.

The legacy `provider-subscription-claude` surface fails closed before configuration mutation or
client execution. Anthropic currently prohibits third-party products from offering Claude.ai
login or routing Free, Pro, or Max subscription credentials. Use `provider-anthropic`,
strict-free OpenRouter, a custom endpoint, or the official Claude Code product instead.

The selected home must remain a canonical owner-private directory rather than a symlink. Before
using the daemon bearer, the client validates that parent boundary, opens `connection.json`
without following a symlink, caps it at 64 KiB, and requires a literal-loopback HTTP origin.
Ordinary daemon requests have a 30-second whole-request deadline; named maintenance operations use
ten minutes, while timeline SSE reconnects from its last verified cursor without a whole-stream
deadline. Successful and error envelopes must name the exact API version, and terminal output is
rendered from typed bounded data rather than raw daemon bytes.

The CLI covers sessions, tasks, durable delegation inspection, approvals, effects, memory,
compaction, extensions, signed webhook, Telegram, and exact-DM Discord channels, durable recurring schedules,
status/metrics/doctor, scriptable exact 1–31-day terminal usage, a temporary least-authority interactive loopback dashboard, safe backup verification
and stopped-home activation, complete/scoped export,
retention GC, bounded drain, service installation, brokered provider/web setup, workspace grants,
separate create/replace-file activation, concurrent queue/steer/interrupt chat admission, bounded
owner-explicit local UTF-8 text-file admission, durable
correlation-filtered bounded provider-text/model/tool progress, explicit `/act` chat turns with non-blocking
exact-subject `/approve` or `/deny` commands, `/edit` turns for digest-preconditioned atomic
existing-file replacement from complete content or bounded ordered exact-text edits with expected
occurrence counts, `/manage` turns for one exact create-directory, digest-bound no-overwrite file
move/removal, or empty-directory removal, high-risk `/run` turns whose approval preview verifies
and renders exact normalized argv, inline governed-memory remember/search/correct/lifecycle
commands, a stopped-daemon data-only skill lifecycle, and configuration rollback.

Installed-program lifecycle is separately provenance aware. `install-status` verifies the complete
published payload and distinguishes managed archives from Debian, RPM, Arch, development, and
unknown layouts. `update`, `repair`, `rollback`, and `uninstall` emit no-mutation plans by default
and require explicit approval for an owner-local mutation; native packages always hand control back
to their package database. The bundled attested bootstrap lets `update` compare the exact target
state schema before a same-schema archive swap. Approved apply runs in a separate restartable user
service, records its phases, backs up and drains first, health-gates commit, and automatically
restores a qualified prior slot on failure; `update-status` inspects that durable transaction.
Approved archive uninstall also removes only an exact generated owner service; `service remove`
provides the same plan-first cleanup independently. Bash/Zsh/Fish completion is generated offline.

`chat --session-id SESSION_ID` also reconstructs local watchers for the retained active task and
pending durable inputs; leaving the REPL never cancels accepted daemon work. `session list` returns
up to 100 recently updated sessions for the exact authenticated binding without crossing into a
Telegram, Discord, or webhook identity. Conversation continuity is compiled by the daemon from a bounded,
same-context-epoch suffix of canonical successful turns, not from client-local transcript state;
the latest user input is mandatory and compaction/revocation boundaries are enforced before
provider dispatch.

Inside `chat`, `/attach PATH` queues the same governed attachment with a fixed safe prompt; the
complete remainder after `/attach ` is the path, so spaces do not require shell parsing.
`session send-file SESSION_ID PATH` is the scriptable form and opens only an explicitly selected no-follow regular file,
accepts a fixed UTF-8 text/source extension allowlist up to 256 KiB, rejects empty/NUL/symlink or
unsupported input, and submits digest/size/media/name metadata plus exact bytes under an explicit
untrusted attachment frame. The host path never enters the daemon request. `--prompt`,
`--delivery`, and `--idempotency-key` use the normal durable input boundary. This is text input,
not image/audio/video or arbitrary binary upload.

`mealyctl --home "$HOME/.mealy" dashboard` preflights six read-only daemon projections and serves
a random numeric-loopback port until Ctrl-C. The page shows operational health and also provides a
fixed typed interaction subset: create a session, submit bounded queue/steer/interrupt input, poll
its durable timeline, resolve an exact digest-bound approval, cooperatively cancel its active
task, inspect exact effect/attempt evidence, or reconcile one linked `outcome_unknown` attempt from
a non-empty bounded external-evidence object. It can also create one schedule from an exact
definition, inspect its bounded newest occurrence history, and issue revision-fenced pause,
resume, or terminal cancel commands. Creation proposes a canonical UUIDv7 resource key, retains
that key and definition across an ambiguous manual retry, reconciles an exact existing schedule,
and rejects different semantics under the same key. Lifecycle transitions are never retried
automatically. General administration remains CLI-only. A governed-memory panel uses fixed namespace/search/detail
queries and exact revision-fenced proposal, explicit owner-approved activation, correction,
pin/unpin, expire, reject, and delete/scrub commands. Proposal and correction construct one
digest-bound owner provenance source from a stable browser command key and reconcile it before a
manual retry; no memory command silently activates retrieval. It has no arbitrary-proxy route. The daemon bearer stays inside
`mealyctl`; the no-store page receives a separate 256-bit ephemeral capability protected by exact
Host, exact mutation Origin, constant-time validation, body/concurrency limits, and strict CSP.
An exact 30-day view groups terminal root, delegated, and validation-run settlement by UTC
completion day; empty days are omitted and every run's complete settled usage is attributed to its
completion day. A separate exact task view renders canonical provider/tool/delegation calls,
retries, input/output tokens, output bytes, and settled/charged versus active-reserved
provider-neutral cost microunits. Neither view converts those values into an external invoice or
invents unsupported billing axes.
An extension panel adds Origin-protected bounded inventory/detail and data-only manifest/grant
review. Enable derives every selectable capability, mount, destination, secret reference, and
process flag from that exact manifest, requires typed confirmation, health-probes before authority,
and binds the rendered revision; disable and terminal revoke use the same preflight. Identical
already-completed transitions are reconciled without a second daemon mutation. Package
install/stage, filesystem roots, upgrades, and arbitrary invocation remain CLI-only. Never expose
this port remotely.

External-provider runs may expose `agent.delegate` to the model. Inspect—not create or widen—the
resulting owner-scoped child graphs with:

```sh
mealyctl --home "$HOME/.mealy" delegation list --limit 20
mealyctl --home "$HOME/.mealy" delegation status DELEGATION_ID
mealyctl --home "$HOME/.mealy" task status CHILD_TASK_ID
mealyctl --home "$HOME/.mealy" task replay CHILD_TASK_ID
```

The status response includes the exact parent/child run IDs, child task ID, effective capability
intersection, separate child budget, terminal state, and structured `delegation://result`. Parent
cancellation propagates to an active child; direct task cancellation remains the only cancellation
command so there is no second control plane.

`/remember TEXT` is an explicit owner command: it proposes the exact private fact with a generated
content-digest citation and then separately owner-authorizes that revision. `/memories [QUERY]`,
`/memory-status`, `/memory-activate`, `/memory-correct`, `/memory-expire`, `/memory-reject`, and
`/memory-delete` expose the governed lifecycle without sending those slash commands to the model.
The REPL prints and can locally switch its retrieval namespace with `/memory-use`; switching grants
no authority. The scriptable equivalent is `memory remember --workspace WORKSPACE CONTENT
--approve`. A partial activation reports the durable proposal/revision IDs for recovery.
`/history QUERY` (or `session search QUERY`) performs newest-first literal transcript search across
the exact local binding, returning bounded UTF-8 excerpts, canonical IDs, and complete-content
digests without crossing into Telegram/Discord/webhook sessions.

`config provider`/`provider-fallback` activate `OpenAI` Responses, while
`provider-anthropic`/`provider-fallback-anthropic` activate the independently implemented
Anthropic Messages contract. `provider-openrouter` is an explicit preset for OpenRouter's stateless
Responses API beta; it brokers `OPENROUTER_API_KEY`, defaults the official API base/residency, and
retains the same live bounded compatibility probe. This deployment requires an exact `:free`
OpenRouter model with complete zero pricing and no unsupported billing axes; the account-filtered
catalog exposes the fields needed to enforce that review. `provider-local`/`provider-fallback-local` are credentialless presets
for an OpenAI Responses-compatible server on a literal loopback IP; they record local residency,
zero provider price, and no broker entry. All commands request protocol-specific SSE by default and
may be mixed only in one same-residency/locality chain. Use `--disable-streaming` for a terminal-only compatible
endpoint. Streamed text remains an
explicitly non-authoritative preview until its terminal response is validated and committed. The
same activation runs a bounded live selected-model probe before writing config or a new broker
entry. `--skip-connectivity-test` is an explicit staged/offline escape and is reported in output;
do not treat a skipped activation as production-tested. After activating a replacement
`--secret-id`, `config provider-secret-revoke OLD_ID --approve` removes only an unreferenced broker
entry while stopped and leaves active configuration fail closed.
`config provider-fallback-remove PROVIDER_ID --approve` removes only that exact routing entry,
retains its broker credential for explicit later revocation/rollback, and preserves the remaining
order. Replacing a primary preserves the existing chain only when the complete new chain still
passes identity/residency/locality validation; otherwise the replacement fails without mutation.
Use stopped-home `config provider-list` first to review the validated exact order, limits, prices,
residency, models, and opaque credential identities without resolving credential values.

Before activation, `config provider-models`, `config provider-models-anthropic`,
`config provider-models-openrouter`, and
`config provider-models-local` perform a read-only live catalog request. The first two use a
credential scoped to the request; OpenRouter also uses a request-scoped key, while the local command sends no authorization header and accepts only
a literal-loopback base. All disable proxies and redirects, enforce a
30-second deadline, a 1-MiB body ceiling, safe metadata validation, optional `--contains`
filtering, and a 500-record output ceiling. Anthropic pagination continues with
`--after-id NEXT_AFTER_ID`. OpenAI's catalog supplies only basic identifiers/ownership metadata;
Anthropic may also supply context and maximum-output limits. OpenRouter's account-filtered catalog
supplies limits and posted per-token prices; Mealy converts representable values exactly and marks
pricing incomplete when any fixed/image/search/reasoning/cache axis is nonzero. The OpenAI and
Anthropic catalogs do not supply prices. Activation always requires explicit reviewed values.
Discovery never
writes the Mealy home or echoes a credential/failure body.

For a clean home, the equivalent guided local activation is:

```sh
mealyctl --home "$HOME/.mealy" setup --provider local \
  --model YOUR_LOCAL_RESPONSES_MODEL \
  --context-tokens YOUR_CONSERVATIVE_CONTEXT_LIMIT --approve
```

The lower-level discovery/activation workflow remains available after an existing daemon home has
been drained:

```sh
mealyctl --home "$HOME/.mealy" config provider-models-local \
  --base-url http://127.0.0.1:11434/v1
mealyctl --home "$HOME/.mealy" config provider-local \
  --base-url http://127.0.0.1:11434/v1 \
  --model YOUR_LOCAL_RESPONSES_MODEL \
  --context-tokens YOUR_CONSERVATIVE_CONTEXT_LIMIT \
  --maximum-output-tokens 4096 --approve
```

The server must implement `POST /v1/responses`; a successful `/v1/models` listing alone is not
compatibility evidence. Activation therefore performs the same bounded selected-model probe used
for credentialed Responses endpoints.

`skill inspect/install/status/list/update/enable/disable` manages strict `mealy.skill.v1` bundles.
Inspection executes nothing and accepts only an exact `manifest.json` plus digest/size-pinned
instruction and passive-resource files. Installation is approved but inert; enabling is a second
digest-fenced decision, and an update removes prior instruction authority by staging the new
revision disabled. Enabled instructions and provenance enter new context epochs under aggregate
bounds. Passive resources remain unloaded until the separately governed, read-only
`skill.read_resource` tool requests a bounded cited chunk. `requiredTools` are visible references
and never grant authority. See [`docs/QUICKSTART.md`](../../docs/QUICKSTART.md) for the manifest and
copy-paste lifecycle.

`config mcp-inspect` executes one exact native ELF MCP stdio server in the Linux no-network
Bubblewrap boundary and prints its complete `2025-11-25` tool inventory without changing
authority. `mcp-add --allow-tool NAME --approve` re-inspects it, copies exact bytes into private
content-addressed storage, and exposes only selected full schema-pinned definitions after restart.
`mcp-list` is read-only; `mcp-disable`, `mcp-enable`, and `mcp-revoke` require a stopped home and
explicit approval. Enable performs fresh full-toolset verification. Direct server arguments are
non-secret configuration, not a credential path. See
[`docs/QUICKSTART.md`](../../docs/QUICKSTART.md) for the isolation, drift, cancellation, replay,
backup, unsupported-platform, and recovery boundaries.

`config browser-inspect BUNDLE` verifies a complete Chrome Headless Shell inventory and runs only
its version probe in a no-network/no-home namespace. After web destinations are enabled,
`browser-add BUNDLE --approve` copies exact bytes into content-addressed private storage and must
pass a real fresh-profile CDP/navigation/render self-test before publishing configuration.
`browser-list` is read-only. `browser-disable`, `browser-enable`, and `browser-revoke` require the
stopped-home lock and approval; enable repeats complete byte/product/CDP/render verification, while
disable/revoke retain runtime bytes for rollback. `web-disable` refuses an enabled browser. The
managed `fetch-browser-runtime.sh` downloads only the repository size/SHA-pinned Linux x86_64
archive. The resulting model tool is GET/HEAD-only `browser.snapshot`: it may follow one exact
same-origin link, activate one exact native form-free `type=button`, or fill one exact native
non-password textbox/searchbox. An optional form action is reconstructed as a same-origin GET with
only that named field; page input/change/submit events, sibling/hidden controls, POST, arbitrary
click/type/form behavior, uploads, and unbounded/owner-path downloads remain denied. One exact
accessible same-origin attachment link can be captured into at most 512 KiB of digest/base64
evidence in the ephemeral profile; persistence and personal-profile authority remain denied. See
[`docs/QUICKSTART.md`](../../docs/QUICKSTART.md) for the pinned acquisition, cgroup, sandbox,
network, evidence, replay, backup, and recovery boundaries.

Telegram setup reads the Bot API token from `TELEGRAM_BOT_TOKEN` (or an explicitly named
environment variable), never a command argument:

```sh
export TELEGRAM_BOT_TOKEN='replace-with-token'
mealyctl --home "$HOME/.mealy" channel telegram-pair
unset TELEGRAM_BOT_TOKEN

mealyctl --home "$HOME/.mealy" channel telegram-list
mealyctl --home "$HOME/.mealy" channel telegram-status BINDING_ID
mealyctl --home "$HOME/.mealy" channel telegram-revoke BINDING_ID \
  --expected-revision REVISION
```

The command verifies the bot, prints a high-entropy one-time `/pair` command, accepts only an exact
human private chat during a 30–300 second window, and fences every earlier update before it creates
the binding. `telegram-create --user-id ... --chat-id ...` remains an advanced manual alternative.
The response's `sessionId` can be supplied to `schedule create` for remote recurring turns. See
[`docs/QUICKSTART.md`](../../docs/QUICKSTART.md) for bot commands, attachment limits, approvals,
retry behavior, and token rotation.

Discord setup likewise keeps its bot token out of argv and configuration, but deliberately binds
only one explicit human-to-bot direct message:

```sh
export DISCORD_BOT_TOKEN='replace-with-token'
mealyctl --home "$HOME/.mealy" channel discord-pair --channel-id DM_CHANNEL_ID
unset DISCORD_BOT_TOKEN

mealyctl --home "$HOME/.mealy" channel discord-list
mealyctl --home "$HOME/.mealy" channel discord-status BINDING_ID
mealyctl --home "$HOME/.mealy" channel discord-revoke BINDING_ID \
  --expected-revision REVISION
```

Pairing verifies the Discord API v10 bot, channel type, exact recipient, and random one-time text
before the daemon repeats live verification and fences setup history. `discord-create --user-id
USER_ID --channel-id DM_CHANNEL_ID` is the advanced manual alternative. Discord messages support
the same text controls and approvals as Telegram; attachments and non-DM workflows are ignored by
this least-authority profile. The returned `sessionId` is also a valid schedule destination. See
[`docs/QUICKSTART.md`](../../docs/QUICKSTART.md) for Developer Portal setup, snowflake handling,
pagination, rate limits, nonce delivery, recovery, and rotation.

An encrypted backup is activated only after online/isolated verification returns its exact digest,
the daemon has drained, and the owner explicitly approves that digest:

```sh
export MEALY_BACKUP_PASSPHRASE='a long owner-chosen passphrase'
mealyctl --home "$HOME/.mealy" restore-activate BACKUP_NAME \
  --expected-manifest-digest MANIFEST_SHA256 --approve
unset MEALY_BACKUP_PASSPHRASE
```

The operation atomically exchanges complete sibling homes on supported filesystems and retains the
untouched pre-restore home. It refuses non-secret backups, corrupt evidence, wrong credentials, or
a live daemon.

Cross-schema package rollback is deliberately coordinated by the installed release manager, not
by invoking the hidden home-activation primitive directly. After comparing an automatic migration
snapshot's manifest digest with the digest recorded during upgrade, run:

```sh
"$HOME/.local/share/mealy-manager.sh" rollback-migration \
  --migration-backup SNAPSHOT_NAME \
  --expected-manifest-digest MANIFEST_SHA256 \
  --approve --prefix "$HOME/.local" --home "$HOME/.mealy"
```

The manager binds both release schema identities to the snapshot, passes its stopped-home lock to
the verified newer client without unlocking, atomically exchanges complete homes, and retains the
migrated home for forward recovery. See [`docs/RELEASE.md`](../../docs/RELEASE.md) for the complete
inspection and recovery procedure.
