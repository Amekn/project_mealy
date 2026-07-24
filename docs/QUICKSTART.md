# Quickstart

This guide runs Mealy from Linux source or from a verified tagged release. A successfully
published tag provides attested owner-local archives, `amd64`/`arm64` Debian packages,
`x86_64`/`aarch64` RPMs, and an x86-64 Arch package; the GitHub Releases page and that tag's
workflow evidence are authoritative for whether those assets exist. This guide is suitable for evaluating
the durable agent loop, policy, sandbox, approvals, recovery, replay, memory, extensions, channels,
and operational controls.

Command examples use a per-user `$HOME/.local/bin` installation. Debian, RPM, and Arch packages
instead provide the same commands at `/usr/bin/mealyd` and `/usr/bin/mealyctl`; substituting those
paths does not change the required `--home` value or any lifecycle step. See the
[Linux support contract](LINUX_SUPPORT.md) before installing on a derivative distribution.

## Fast verified Linux install

A published stable release includes an attested rootless bootstrap. It selects the native x86-64
or ARM64 archive, resolves an exact stable tag, verifies the bootstrap, manager, target checksum
manifest, and archive against that tag's release-workflow attestations, verifies the complete
target checksum inventory, and installs beneath `$HOME/.local`. It never uses `sudo`,
starts a service, creates a Mealy home, or requires Rust:

```sh
tmp=$(mktemp -d)
curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --output "$tmp/install-mealy-release.sh" \
  https://github.com/Amekn/mealy/releases/latest/download/install-mealy-release.sh
curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --output "$tmp/ATTESTATION-installers.sigstore.json" \
  https://github.com/Amekn/mealy/releases/latest/download/ATTESTATION-installers.sigstore.json
gh attestation verify "$tmp/install-mealy-release.sh" \
  --repo Amekn/mealy \
  --signer-workflow Amekn/mealy/.github/workflows/release.yml \
  --bundle "$tmp/ATTESTATION-installers.sigstore.json" \
  --deny-self-hosted-runners
chmod 0755 "$tmp/install-mealy-release.sh"
"$tmp/install-mealy-release.sh"
```

The canonical signer identity above applies to v0.1.1 and later. Historical v0.1.0 bundles were
issued as `Amekn/project_mealy` before the repository rename and retain that identity.

Use `--version vX.Y.Z` to select a particular stable release, or `--prefix`/`--home` for custom
paths. Public release metadata/assets are fetched with bounded HTTPS requests, so no GitHub login
or token is required. The bootstrap rejects drafts, prereleases, unsupported architectures, incomplete downloads,
self-hosted provenance, a different signer workflow/ref, and any checksum or inventory mismatch.
It prints the exact `mealyctl setup` and service-install commands after success. Continue with the
prerequisites and first-run checks below before enabling governed tools.

## Native Linux packages

Use the verified `.deb` on Debian 13 or Ubuntu 24.04/26.04, the verified `.rpm` on Fedora 44, and
the verified `.pkg.tar.zst` on current x86-64 Arch. The [release guide](RELEASE.md) gives exact
download, attestation, checksum, install, upgrade, and removal commands. Native packages are
passive: installing one does not create a user, start a service, or modify `$HOME`.

> **Current capability boundary:** Mealy can now use explicit same-trust fallback chains containing
> independently implemented `OpenAI` Responses and Anthropic Messages endpoints for bounded,
> durable conversation, or its deterministic local fixture provider for offline conformance
> testing. On Linux, a real-provider profile can list,
> stat, read, and search only explicitly granted workspace roots through logical paths. An
> explicitly enabled profile can also perform bounded web search/fetch. On conforming Linux hosts,
> a separately enabled writable-workspace grant permits explicit `/act` turns to create one new
> file and `/edit` turns to replace one bounded existing file only while its exact current SHA-256
> still matches, after owner approval. Replacement accepts complete content or bounded ordered
> exact-text edits with expected occurrence counts. Explicit `/manage` turns can create one
> directory beneath an existing parent, move one digest-matched bounded regular file without
> overwrite, remove one digest-matched bounded regular file, or remove one empty directory. An
> additional stopped-daemon grant can expose a root-controlled,
> digest-pinned installed executable to explicit high-risk `/run` turns. On Linux x86_64, an
> independently enabled content-pinned browser can navigate/render a URL, return accessibility
> evidence and a screenshot, follow one exact GET-only link, activate one exact native form-free
> button, fill one exact non-password text/search control with an optional selected-field-only
> same-origin GET, or capture one exact same-origin attachment up to 512 KiB in a fresh agent
> profile. It cannot perform arbitrary keyboard/click events, POST or multi-control forms, uploads,
> owner-path downloads, or persistent/personal-profile browsing. A
> first-party Telegram bot channel supports
> an exact user/chat allowlist, durable conversation controls, bounded text attachments, approvals,
> restart recovery, scheduled turns, and guided private-chat pairing. Provider model discovery is
> now live and credential-scoped for both provider protocols; the OpenRouter preset also normalizes
> its account-filtered catalog's posted text-token prices, while other provider prices still require
> operator-verified configuration. Broader tools remain outside the current contract. Published
> release and external production-acceptance evidence are properties of a specific tag and must be
> verified from that tag's workflow rather than inferred from a source checkout.

## Prerequisites

- GitHub CLI with `gh attestation verify --bundle` support for the stable-release bootstrap and
  provenance checks. The published offline Sigstore bundles remove any GitHub login/token
  requirement. Source builds do not need `gh`.
- For source builds only, Rust `1.96.0` through `rustup`; the repository's
  `rust-toolchain.toml` selects it automatically.
- For source builds only, a supported SQLite build, C toolchain, and normal Rust native-build
  prerequisites.
- On Linux, Bubblewrap at `/usr/bin/bwrap` for sandboxed effects, MCP, extensions, and browser calls.
- On Ubuntu 24.04+, a reviewed Bubblewrap/AppArmor user-namespace policy. The distribution's
  default restriction can otherwise fail with `RTM_NEWADDR: Operation not permitted`. Do not make
  Bubblewrap setuid or disable the host mitigation globally as a routine Mealy install; use a
  distro profile or dedicated host policy and require `mealyctl doctor` to report the sandbox
  profiles enforceable.
- For the optional Linux x86_64 browser, `curl`, `unzip`, and `sha256sum`; Mealy's helper downloads
  only the repository-pinned Chrome Headless Shell archive and verifies its exact byte count and
  SHA-256 before extraction.
- A root-controlled regular `/usr/bin/ldd` on Linux so Mealy can discover only the dynamic runtime
  files required by its worker. Mealy invokes this exact helper with an empty environment; it does
  not resolve a substitute through the owner's `PATH`.
- For published owner-local archives, GNU tar/coreutils, `jq`, and `flock` (normally from
  `util-linux`) for bounded archive, manifest/SBOM, and stopped-home verification, plus glibc 2.39
  or newer. The bootstrap checks this before downloading the architecture payload. A verified
  Debian package instead declares Bubblewrap, CA certificates, `libc-bin >= 2.39` (for the exact
  trusted `/usr/bin/ldd` helper), `libc6 >= 2.39`, and `libgcc-s1`; it does not require a Rust
  toolchain.

Fedora:

```sh
sudo dnf install bubblewrap curl gcc jq unzip util-linux
```

Ubuntu or Debian:

```sh
sudo apt-get update
sudo apt-get install --yes apparmor-profiles apparmor-utils bubblewrap build-essential curl jq unzip util-linux
```

Arch Linux:

```sh
sudo pacman -Syu --needed bubblewrap curl jq unzip util-linux
```

The optional pinned Chrome Headless Shell is dynamically linked. On the supported Ubuntu LTS
and Debian 13 releases, install its direct runtime libraries and a deterministic basic font set
before `browser-add`:

```sh
sudo apt-get install --yes \
  fonts-liberation libasound2t64 libatk-bridge2.0-0t64 libatk1.0-0t64 \
  libatspi2.0-0t64 libdbus-1-3 libexpat1 libgbm1 libglib2.0-0t64 libnspr4 \
  libnss3 libudev1 libx11-6 libxcb1 libxcomposite1 libxdamage1 libxext6 \
  libxfixes3 libxkbcommon0 libxrandr2
```

The Debian package lists these libraries as optional `Suggests`; RPM and Arch packages carry
equivalent weak dependencies for the helper, font, and extraction tools. Core daemon/chat use does
not require them.
`browser-inspect` and `browser-add` still execute the exact downloaded runtime's `--version`
inside its no-network sandbox and fail closed when the host loader cannot satisfy it.

Ubuntu 24.04 additionally restricts unprivileged user namespaces through AppArmor. Do not disable
that host-wide protection merely to run Mealy. Noble's current `apparmor-profiles` package provides
`bwrap-userns-restrict` as a disabled extra profile: it permits Bubblewrap to build the namespace
but strips capabilities from the executed child. Review the installed profile because enabling it
applies to every `/usr/bin/bwrap` invocation on the host, then explicitly copy and enforce it:

```sh
sudo install -m 0644 \
  /usr/share/apparmor/extra-profiles/bwrap-userns-restrict \
  /etc/apparmor.d/bwrap-userns-restrict
sudo apparmor_parser -r -K /etc/apparmor.d/bwrap-userns-restrict
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=1
sudo grep -Fx 'bwrap (enforce)' /sys/kernel/security/apparmor/profiles
sudo grep -Fx 'unpriv_bwrap (enforce)' /sys/kernel/security/apparmor/profiles
bwrap --die-with-parent --new-session --unshare-user --unshare-pid \
  --unshare-net --ro-bind / / -- /bin/true
```

The two profile queries and final command must all exit zero. Loading the exact profile with
`apparmor_parser` avoids `aa-enforce` scanning and rejecting an unrelated malformed optional
profile. If the distro profile is absent or conflicts with another local policy, stop and use a
dedicated reviewed host policy rather than making Bubblewrap setuid or globally setting
`kernel.apparmor_restrict_unprivileged_userns=0`. After Mealy starts, require
`mealyctl doctor` to report the `observe` and `workspace_write` profiles `enforceable`; Mealy fails
closed when it cannot enforce the requested worker profile.

macOS and Windows are outside the active source, package, CI, and production support contract. The
historical macOS preview remains available from `v0.1.0`, but it is archived and unmaintained.

## Build release binaries

For a tagged published build, prefer the attested archive and verification flow in
[`RELEASE.md`](RELEASE.md). No release is implied until its tag workflow has actually published
those assets. To build the current checkout from source, continue below.

From the repository root:

```sh
scripts/build-release-binaries.sh
```

The release builder gives compiler-generated source locations stable virtual prefixes and rejects
host-specific repository, Cargo-cache, or user-home paths in either binary. Ordinary debug builds
may continue to use Cargo directly; distributable binaries must use this boundary.

For a stable per-user installation path:

```sh
install -Dm755 target/release/mealyd "$HOME/.local/bin/mealyd"
install -Dm755 target/release/mealyctl "$HOME/.local/bin/mealyctl"
```

Ensure `$HOME/.local/bin` is on `PATH`, or use the absolute paths below.

## Guided first run (recommended)

`mealyctl setup` initializes a clean owner-private home and activates one provider while the daemon
is stopped. It prompts only for non-secret provider/model/limit/price choices. For a remote
provider, put the key in its standard environment variable before starting the wizard; the key is
read once, used for a bounded connectivity/model probe, brokered below the private home, and never
printed or written to `config.json`.

OpenAI example:

```sh
export OPENAI_API_KEY='replace-with-your-api-key'
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" setup
unset OPENAI_API_KEY
```

Choose `OpenAI`, `Anthropic`, `OpenRouter`, or a credentialless literal-loopback local endpoint.
The wizard shows the exact non-secret API base, model, limits, price inputs, streaming/probe state,
credential environment-variable name, and provider-config digest before it requires the exact word
`APPROVE`. It creates no provider state when that approval is denied. On success it prints the
exact daemon, `doctor`, and `chat` commands to run next.

Keep `--home` as a real owner-private directory (normally mode `0700`), not a symlink. The client
rejects a redirected or group/world-accessible home before reading `connection.json`; it then opens
that descriptor without following a symlink, caps it at 64 KiB, and accepts only the generated
32-byte bearer for a literal-loopback HTTP origin. If copied state has broader permissions, repair
the directory deliberately before starting Mealy rather than bypassing this boundary.

For a local Responses-compatible server, all required choices can also be supplied directly:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" setup \
  --provider local \
  --model YOUR_LOCAL_RESPONSES_MODEL \
  --context-tokens YOUR_CONSERVATIVE_CONTEXT_LIMIT \
  --maximum-output-tokens 4096 \
  --approve
```

The live probe remains mandatory by default. `--skip-connectivity-test` deliberately creates only
a staged, unverified configuration and is labeled that way in both the review and JSON response;
rerun tested setup before treating the installation as production-ready. The lower-level
`config provider-*` commands later in this guide remain available for model discovery, custom
identities, fallback chains, rotation, and advanced automation.

## Alternative: run the offline conformance profile

This path is an alternative to guided real-provider setup, not a step that follows it. Skip
`mealyctl setup`, or use a separate home such as `$HOME/.mealy-offline`; a home that already has an
activated remote provider will continue to use that provider.

Start the daemon in one terminal:

```sh
"$HOME/.local/bin/mealyd" --home "$HOME/.mealy-offline"
```

Without configuration changes, the daemon uses its deterministic fixture provider. It creates an
owner-private home, initializes schema-versioned configuration and SQLite state, publishes an
owner-only loopback connection descriptor, completes recovery, and then prints its readiness
address.

In another terminal, verify the installation:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy-offline" health
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy-offline" status
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy-offline" doctor
```

`doctor` is the authoritative check. On a full Linux installation it should report the control
plane ready and the `observe`/`workspace_write` Bubblewrap profiles enforceable. Profiles that the
host cannot enforce are reported as denied rather than silently downgraded.
The daemon completes full SQLite, FTS5, and foreign-key integrity diagnostics before it starts
worker concurrency. Runtime `health`/`doctor` responses use bounded online schema checks; backup,
restore, stopped-soak, and release gates repeat deep integrity checks on a consistent boundary.

The remaining examples use `$HOME/.mealy`; substitute `$HOME/.mealy-offline` consistently if you
chose the offline alternative.

## Open the interactive operations dashboard

With the daemon running, start a temporary dashboard in another terminal:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" dashboard
```

Open the printed numeric-loopback URL and leave that command running. The dashboard preflights and
combines six authenticated operational projections: status, doctor, the 20 most recent
exact-binding sessions, pending approvals, schedules, and exact settled usage for the trailing 30
days. From its Conversation panel you can
create a session, submit queue/steer/interrupt input, follow a bounded live durable timeline, and
request cooperative cancellation of the active task. Pending approvals render the complete exact
subject and digest before an explicit approve/deny confirmation. Input, approval, and cancellation
commands carry stable idempotency keys, including ambiguous browser retries. The Effect recovery
panel can load one exact effect and optional attempt from IDs copied from an approval/timeline (or
through its Inspect buttons). It renders normalized arguments, logical targets, policy/approval,
fence, error classification, and immutable outcome evidence directly from canonical API views.
Only a linked effect and attempt that both remain `outcome_unknown` enable reconciliation. The
owner must choose `succeeded` or `failed`, enter a non-empty external-evidence JSON object of at
most 32 KiB, and confirm the exact effect, attempt, revision, tool, targets, and evidence size.
Evidence is durable, so include only secret-free receipts/observations and never credentials.
Ambiguous reconciliation retries reuse the same key; the operation is never redispatched.

The 30-day settled usage panel includes terminal root, delegated, and validation runs for the exact
authenticated binding. It groups by UTC completion day, omits empty days, and shows complete
settled run/call/retry/token/configured-cost totals; an unsettled terminal reservation makes the
report fail closed. The Task usage and cost panel accepts an exact task UUID or can be opened from a `task.created`
timeline row. It renders the complete canonical task projection and separately shows recorded
provider/tool/delegation calls, retries, input/output tokens, output bytes,
`usedCostMicrounits`, and `reservedCostMicrounits`. Terminal tasks are accepted only when every
active reservation is zero. Microunits are the provider-neutral configured pricing snapshot used
by Mealy's routing and budget ledger; they are not an upstream invoice or currency conversion.
Mealy does not guess fixed, media, search, reasoning, cache, tax, credit, or other unsupported
billing axes. Compare provider billing separately when financial reconciliation matters.

The same exact terminal history is available as versioned JSON for automation:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" usage --days 30
```

The Schedules panel can create a schedule for an exact existing session, then loads the canonical
definition and at most 50 newest durable occurrence runs before enabling lifecycle controls. The
page generates a canonical UUIDv7 resource key and retains that exact key and immutable definition
after an ambiguous response. A retry reconciles the already-created schedule; reusing the key with
different semantics fails closed. Action-authorized creation requires typing `CREATE SCHEDULE_ID`.
Pause, resume, and terminal cancel bind the displayed revision and accept only a response for the
same schedule at revision +1. Cancellation requires a typed schedule-ID confirmation; resuming a
schedule authorized to submit approval-required action prefixes does too. Lifecycle commands have
no blind retry path: after an ambiguous response the page re-reads exact status/revision evidence,
and the owner decides from that evidence. The reviewed CLI remains available for scripted creation.

The Governed memory panel defaults to the same ordinary namespace printed by `chat`; an owner can
enter another exact namespace already authorized by canonical context-epoch evidence. Namespace
lists include up to 1,000 fully validated logical memories, lexical search returns at most 100
active hits under an explicit maximum sensitivity, and exact detail renders the complete immutable
revision/source history. Proposed content is capped at 48 KiB in this UI. Proposal is deliberately
separate from activation: a stable browser command key becomes a hashed `owner://` provenance
locator paired with the exact content digest, so an ambiguous manual retry first reconciles durable
state instead of creating a duplicate. Activation requires typing the exact memory ID and always
records `owner_approval` for the selected proposed revision. Correction uses the same provenance
reconciliation plus an optimistic revision; pin/unpin, expire, reject, and delete/scrub are also
revision fenced. Deletion requires a typed confirmation and retains only governed digest/lifecycle
tombstones. Never enter a raw credential, bearer token, private key, or recovery code—credential
memory is for references only.

The Extensions panel uses Origin-protected POST reads because even secret-free manifests and grants
can reveal sensitive capability, path, destination, and opaque secret-reference metadata. Load the
inventory, inspect an exact extension, and review its full data-only manifest/history before any
transition. Enable starts with only the required read-only health capability selected; choose only
additional manifest-declared capabilities and authority you intend to grant. Filesystem mappings
must use canonical absolute host and sandbox paths. A typed `ENABLE EXTENSION_ID` confirmation
binds the rendered revision, exact current manifest, selected grant, and successful health probe.
Disable removes active authority; typed `REVOKE EXTENSION_ID` is terminal. Every command preflights
canonical state and recognizes an identical already-completed revision +1 result, so an ambiguous
manual retry cannot issue the grant twice. Raw secrets are never accepted—only select a declared
opaque broker reference. Use the CLI for package install/stage, upgrades, installation roots, and
extension invocation.

The adapter has no generic proxy. It cannot change configuration, manage credentials,
install/stage extension packages, rebuild/export the memory index, perform general
recovery, infer aggregate provider billing, or invoke arbitrary daemon routes.
Continue to use the reviewed `mealyctl` commands for those operations.

`mealyctl` first proves all five projections are available, then binds a random `127.0.0.1` port.
The real daemon bearer remains only in the CLI process and never enters the page, URL, browser
storage, or dashboard JSON. The no-store page receives a separate 256-bit lifetime-only capability;
API calls require that capability and the exact numeric Host, while every mutation additionally
requires the exact browser Origin. Strict CSP/frame/resource policies, 64 KiB body and 16 KiB input
limits, typed UUID routes, bounded timeline pages, exact reconciliation-evidence bounds, and
1–100 schedule-history queries, 1,000-extension/1,024-manifest-history projection bounds, plus
separate snapshot/timeline/detail/command concurrency limits
fail closed. Every daemon response is streamed into an 8 MiB ceiling before JSON decoding. Closing the command
destroys the server and capability. Do not publish or
reverse-proxy this port: the dashboard is an owner-local console, not a remote administration
service.

## Chat with Mealy

The simplest first-party surface creates a durable session and tracks multiple accepted inputs
without blocking the prompt while a task is running:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" chat
```

The REPL prints its session ID. Resume it later with `chat --session-id SESSION_ID`; the client
scans up to 100,000 retained events, rediscovers the exact active turn and durable pending inbox
entries, and resumes their local watchers before accepting more input. Plain text and `/queue TEXT`
use normal FIFO delivery, `/steer TEXT` attaches at the next safe boundary, and
`/interrupt TEXT` records cancellation before durably queueing the replacement. These commands
remain available while earlier provider or tool work is in flight. `/act TEXT` explicitly selects
configured medium-risk create-file authority for that one task; `/edit TEXT` selects
digest-preconditioned complete or ordered exact-text replacement of one existing file; `/manage
TEXT` selects one exact path lifecycle operation; `/run TEXT` selects configured
high-risk direct-process authority. Ordinary turns remain read-only.

For a completed prior turn in the same context epoch, the daemon—not the CLI—adds the canonical
user input and committed assistant answer to the next model request in chronological order. It
discovers only the newest 32 successful turns within a 512-KiB history ceiling, then records every
included or token-budget-excluded item in the context manifest. The latest authenticated input is
reserved before optional history; if the baseline and that input cannot fit together, the turn
fails explicitly instead of dispatching a misleading prompt. The newest applicable compaction
replaces its cited raw range. An epoch rotation, including workspace/tool revocation, starts with no
prior-session-derived context; subsequent turns carry only history created under the new epoch.

When a governed effect needs approval, the REPL fetches the immutable effect, verifies that its
normalized arguments match the subject, and renders the exact approval ID, subject digest,
subject, and arguments. Resolve only that rendered subject without blocking other input:

```text
/approve APPROVAL_ID SUBJECT_DIGEST
/deny APPROVAL_ID SUBJECT_DIGEST
```

The client reconnects polling from durable cursors, correlates progress to the exact task, and
reports provider text deltas, model/tool lifecycle events, and final responses. `/quit` stops only
the local watchers; already accepted inputs remain durable in the daemon. Text deltas are marked
non-authoritative previews; only the separately validated terminal provider response can complete
the task.

## Exercise the lower-level session API

Create a session:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" session create
```

Find recent sessions owned by this exact local channel binding, newest updated first:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" session list --limit 20
```

Copy a returned `sessionId` into `chat --session-id SESSION_ID` to resume its active/pending work.
Telegram-owned sessions remain discoverable through `channel telegram-list`; exact channel-binding
isolation prevents a general local session query from silently crossing transport identities.

From the interactive `chat` prompt, queue one local text attachment directly:

```text
you> /attach ./owner selected notes.md
```

Everything after `/attach ` is treated as the literal path, including spaces. The fixed chat
prompt asks the model to use the selected file; use the scriptable command below when a custom
prompt, delivery mode, or idempotency key is required.

Copy the returned `sessionId`, then submit an input and inspect its progress:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" session send SESSION_ID "hello"
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" session send-file SESSION_ID ./notes.md \
  --prompt "Summarize this untrusted document."
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" session status SESSION_ID
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" session watch SESSION_ID
```

The default provider deterministically invokes `fixture.read` and returns a durable evidence
summary. This validates admission, scheduling, context compilation, provider normalization, tool
observation, validation, timeline delivery, and recorded replay; it does not interpret the prompt
as a general model would.

`/attach` and `send-file` share one explicit local text attachment path. It accepts a nonempty no-follow regular
UTF-8 file of at most 256 KiB with a reviewed text/Markdown/JSON/CSV/YAML/TOML/source extension,
computes SHA-256 over the exact bytes, persists only basename/media/size/digest plus content inside
an untrusted frame, and reuses ordinary queue/steer/interrupt and idempotency semantics. Symlinks,
NUL/invalid UTF-8, unsupported extensions, directories, and oversized files fail before API
admission. Files inside Mealy's private home are also rejected, even when explicitly selected, so
an attachment cannot turn `identity.json`, connection metadata, configuration history, or broker
files into model input. It does not provide image/audio/video or arbitrary binary upload.

## Enable a real conversational model

The guided `setup` command above is the preferred clean-home path and needs no bootstrap daemon.
If you are using the lower-level configuration commands below against an existing offline-profile
home, first drain and stop that daemon. To use those lower-level commands from a clean home instead
of the wizard, start and drain the offline profile once:

```sh
"$HOME/.local/bin/mealyd" --home "$HOME/.mealy"
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" drain
```

### Credentialless local Responses server

If an OpenAI Responses-compatible server is already listening on a literal loopback IP, no dummy
API key or broker entry is needed. First inspect its model IDs without changing the Mealy home:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" config provider-models-local \
  --base-url http://127.0.0.1:11434/v1
```

The model-list response does not prove that a model implements `POST /v1/responses`, and compatible
local catalogs generally do not supply trustworthy context/output limits. Choose the exact ID and
declare conservative limits for the server's actual model configuration:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" config provider-local \
  --base-url http://127.0.0.1:11434/v1 \
  --model YOUR_LOCAL_RESPONSES_MODEL \
  --context-tokens YOUR_CONSERVATIVE_CONTEXT_LIMIT \
  --maximum-output-tokens 4096 \
  --approve
```

This preset accepts only literal-loopback HTTP/HTTPS, sends no authorization header, fixes the
residency label to `local`, records provider prices as zero, and writes `credential: null` without
creating a provider-secret broker. It still performs the bounded selected-model Responses probe;
an incompatible model or server leaves the previous configuration unchanged. Add
`--disable-streaming` only if the endpoint implements terminal Responses JSON but not Responses
SSE. After activation, start `mealyd` again and run `mealyctl --home "$HOME/.mealy" chat`.

To add a second local model behind the same trust/locality boundary while stopped:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" config provider-fallback-local \
  --base-url http://127.0.0.1:11434/v1 \
  --model YOUR_LOCAL_FALLBACK_MODEL \
  --context-tokens YOUR_CONSERVATIVE_CONTEXT_LIMIT \
  --maximum-output-tokens 4096 \
  --approve
```

### Authenticated private llama-server over Tailnet

The owner deployment at `https://the-beast.taile6fad0.ts.net/v1` is authenticated and is not a
literal-loopback endpoint, so use the general Responses-compatible adapter rather than the
credentialless local preset. The machine running Mealy must already be able to resolve, reach, and
validate that Tailnet HTTPS origin. Inspect the server's exact model IDs without changing config:

```sh
export LOCAL_API_KEY='replace-with-your-private-endpoint-key'
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" config provider-models \
  --base-url https://the-beast.taile6fad0.ts.net/v1 \
  --credential-env LOCAL_API_KEY
```

After verifying that the selected llama-server model implements `POST /v1/responses`, activate it
with conservative limits from the server's actual launch configuration:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" config provider \
  --provider-id local.tailnet.responses \
  --base-url https://the-beast.taile6fad0.ts.net/v1 \
  --model YOUR_EXACT_LLAMA_SERVER_MODEL_ID \
  --secret-id local-tailnet-primary \
  --credential-env LOCAL_API_KEY \
  --residency private-tailnet \
  --context-tokens YOUR_CONSERVATIVE_CONTEXT_LIMIT \
  --maximum-output-tokens 4096 \
  --input-microunits-per-million-tokens 0 \
  --output-microunits-per-million-tokens 0 \
  --approve
unset LOCAL_API_KEY
```

This is Mealy's preferred frequent/long-running provider for this installation. The activation
probe is still mandatory: a server that exposes only Chat Completions, returns a different model
identity, or lacks the required Responses tool contract is rejected atomically. Add
`--disable-streaming` only when the endpoint supports terminal Responses JSON but not Responses
SSE. The probe may use up to 256 output tokens so that reasoning-capable compatible servers can
finish the bounded request; the configured output limit remains authoritative if it is lower.
Mealy classifies the HTTPS endpoint as remote for routing and secret handling even though it is
privately hosted. A provider's latency value is a routing estimate rather than a minimum call
duration. Provider activation raises a smaller per-call timeout to the estimate plus a bounded
dispatch safety margin when possible and rejects a result beyond the configured wall-time ceiling.

### OpenRouter Responses beta

OpenRouter exposes a stateless OpenAI-compatible Responses API, currently documented as beta. Use
the dedicated authenticated catalog command first; it queries `/api/v1/models/user`, so results
already reflect the key's provider preferences, privacy settings, and guardrails. Mealy then emits
only text-output models that advertise tool support:

```sh
export OPENROUTER_API_KEY='replace-with-your-api-key'
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" config provider-models-openrouter \
  --contains YOUR_MODEL_FAMILY
```

The response carries the best advertised context/output limits and converts OpenRouter's posted
USD-per-token prompt/completion strings exactly into Mealy microunits per million tokens. It also
lists `unsupportedPricingAxes`. Use catalog prices as complete accounting inputs only when
`pricingComplete` and `tokenLimitsComplete` are both true; fixed request, image, search, reasoning,
or cache charges cannot currently be settled by Mealy's two-axis token budget. Catalog presence
does not prove the beta Responses path or every future tool route.

For this installation, select only records whose exact ID ends in `:free`, whose input and output
microunit prices are both zero, whose `pricingComplete` and `tokenLimitsComplete` fields are true,
whose `unsupportedPricingAxes` array is empty, and whose `toolCapable` field is true. This is the
same fail-closed rule used by the reviewed live-provider workflow:

```sh
catalog=$(mktemp)
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" config provider-models-openrouter \
  --limit 500 >"$catalog"
jq -r '.models[] | select(
  (.id | endswith(":free"))
  and .toolCapable == true
  and .pricingComplete == true
  and .tokenLimitsComplete == true
  and .inputMicrounitsPerMillionTokens == 0
  and .outputMicrounitsPerMillionTokens == 0
  and (.unsupportedPricingAxes | length == 0)
) | [.id, .contextTokens, .maximumOutputTokens] | @tsv' "$catalog"
rm -f "$catalog"
```

Activate the exact slug while stopped:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" config provider-openrouter \
  --model YOUR_EXACT_OPENROUTER_SLUG_ENDING_IN_:free \
  --context-tokens YOUR_VERIFIED_CONTEXT_LIMIT \
  --maximum-output-tokens YOUR_VERIFIED_OUTPUT_LIMIT \
  --input-microunits-per-million-tokens 0 \
  --output-microunits-per-million-tokens 0 \
  --approve
unset OPENROUTER_API_KEY
```

The preset defaults to `https://openrouter.ai/api/v1`, `openrouter.responses`, the
`openrouter-primary` broker identity, and `openrouter-api` residency. Supply the official EU
in-region API base and a matching residency label when that is your reviewed boundary. Activation
sets `store: false`, includes full Mealy conversation context because the upstream API is stateless,
and requires the same bounded JSON/SSE compatibility probe as direct Responses providers. Because
OpenRouter labels this API beta, a passing probe is release evidence for the observed contract, not
a promise that the upstream will never change. See the official
[Responses overview](https://openrouter.ai/docs/api/reference/responses/overview),
[user-filtered Models API](https://openrouter.ai/docs/api/api-reference/models/list-models-user),
and [model pricing schema](https://openrouter.ai/docs/guides/overview/models#model-pricing).

Free-model availability and rate limits can change. Re-run account-filtered discovery before
activation or acceptance; never remove the `:free` suffix or substitute a merely low-cost model.

### OpenAI and Claude subscription sign-in

A ChatGPT subscription is not an OpenAI Platform API key. Mealy supports that owner-local account
only by launching the official Codex client that is already signed in with ChatGPT. It does not
read, copy, refresh, or store the client's OAuth material:

```sh
codex login status
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" config provider-subscription-openai \
  --model YOUR_EXACT_CODEX_SUBSCRIPTION_MODEL \
  --context-tokens YOUR_CONSERVATIVE_CONTEXT_LIMIT \
  --maximum-output-tokens 4096 \
  --approve
```

Claude subscription access uses the same boundary around an already signed-in official Claude
client:

```sh
claude auth status
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" config provider-subscription-claude \
  --model YOUR_EXACT_CLAUDE_SUBSCRIPTION_MODEL \
  --context-tokens YOUR_CONSERVATIVE_CONTEXT_LIMIT \
  --maximum-output-tokens 4096 \
  --approve
```

If PATH lookup is ambiguous, add `--executable-path /absolute/path/to/the/official/client`. Mealy
canonicalizes that path, records its SHA-256, and rechecks the bytes before every request. The
official process receives no OpenAI, Anthropic, OpenRouter, or local API-key variables; client
tools, connectors, project instructions, session persistence, and writable execution are disabled.
Only a bounded JSON conversation/tool envelope enters stdin, and only schema-valid decision and
usage output is accepted. Updating the official client changes its digest and deliberately requires
stopped-home reactivation. Expired or invalid client login fails the connectivity probe without
replacing the previous provider.

Activation raises the current per-provider deadline only when needed to cover the declared
routing-latency estimate (60 seconds by default) and refuses to exceed the configured total run
wall-time bound. Mealy also reserves a conservative, capability-recorded allowance for input
tokens added by the official client outside the normalized conversation; the provider's reported
usage must still fit that durable reservation before settlement succeeds.

The configured output-token value is an acceptance ceiling checked against client-reported usage;
the subscription clients do not currently expose the same exact upstream `max_output_tokens`
control as the direct APIs. Use the private llama-server or zero-price OpenRouter route for
frequent, long-running, unattended, or release-acceptance work. Subscription availability, account
limits, and official-client terms remain upstream constraints, and these commands are not a way to
turn a personal subscription into a general API credential.

### Credentialed OpenAI or Anthropic

With the daemon stopped, export the credential and first list the models accessible to that exact
account. Discovery is read-only and does not require an initialized Mealy home:

```sh
export OPENAI_API_KEY='replace-with-your-api-key'
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" config provider-models \
  --contains YOUR_MODEL_FAMILY
```

The live OpenAI Models API returns identifiers and basic ownership/creation metadata. It does not
say whether every returned identifier supports Responses, and it does not return context limits,
output limits, or prices. Mealy therefore emits those fields as unavailable and never fills policy
budgets from a guessed catalog. Select an exact model, verify its current Responses support,
limits, and billing tier in the [official model documentation](https://developers.openai.com/api/docs/models)
and [official pricing guide](https://developers.openai.com/api/docs/pricing), then activate it:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" config provider \
  --model YOUR_EXACT_OPENAI_MODEL \
  --context-tokens YOUR_VERIFIED_CONTEXT_LIMIT \
  --maximum-output-tokens YOUR_CHOSEN_OUTPUT_LIMIT \
  --input-microunits-per-million-tokens YOUR_VERIFIED_INPUT_PRICE \
  --output-microunits-per-million-tokens YOUR_VERIFIED_OUTPUT_PRICE \
  --approve
unset OPENAI_API_KEY
```

These numeric values are enforced policy inputs, not inferred defaults. One currency unit equals
`1,000,000` microunits;
for example, a price of 1.25 units per million tokens is `1,250,000`. Conservative overestimates
fail closed against Mealy's cost budget; underestimates weaken that budget and must not be used.

For Anthropic, query its separate Models contract first:

```sh
export ANTHROPIC_API_KEY='replace-with-your-api-key'
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" config provider-models-anthropic \
  --contains claude
```

Anthropic currently advertises `contextTokens` and `maximumOutputTokens` in this API when known;
zero or absent provider values are rendered unavailable. Prices are not part of the Models API.
If `providerHasMore` is true, repeat with `--after-id NEXT_AFTER_ID`. Verify the selected model and
limits in the official [Models API](https://platform.claude.com/docs/en/api/models/list) and its
current price in the official [API pricing page](https://claude.com/pricing), then configure the
distinct Messages adapter. Use the exact versioned ID returned by discovery, not a moving alias:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" config provider-anthropic \
  --model YOUR_EXACT_CLAUDE_MODEL_ID \
  --context-tokens YOUR_VERIFIED_CONTEXT_LIMIT \
  --maximum-output-tokens YOUR_CHOSEN_OUTPUT_LIMIT \
  --input-microunits-per-million-tokens YOUR_VERIFIED_INPUT_PRICE \
  --output-microunits-per-million-tokens YOUR_VERIFIED_OUTPUT_PRICE \
  --approve
unset ANTHROPIC_API_KEY
```

All discovery commands use one no-proxy/no-redirect GET with a 30-second deadline, a 1-MiB body
ceiling, at most 500 emitted records, optional case-insensitive filtering, strict safe metadata
validation, and protocol-appropriate authentication (none for the local preset). They never write configuration or broker state,
and an error reports only a safe status/category rather than the response body or credential.

This path uses `POST /v1/messages`, `x-api-key`, and the pinned stable
`anthropic-version: 2023-06-01` contract. Mealy does not request Anthropic prompt caching; a
response that unexpectedly reports cache creation/read tokens fails closed because the configured
uncached price snapshot cannot settle those tiers exactly.

The command refuses a live daemon, validates the non-secret provider settings, reads the credential
from the named environment variable without accepting it as an argument, and preflights any
existing broker identity. Before activation it makes one live, no-tools request to the selected
model with at most 64 output tokens, a 30-second deadline, no proxy/redirect, and a 1-MiB response
bound. Responses activation also sets `store: false`; Anthropic activation sends only the bounded
Messages fields documented above. The selected JSON or SSE contract must return a completed
response. HTTP, authentication, malformed, oversized, incomplete, or transport failure leaves `config.json` and
the credential broker unchanged and never echoes the response body or credential. This probe can
incur a small provider charge.

After the probe passes, the command writes the credential to the owner-private broker, records
only an opaque broker identity in `config.json`, and preserves the previous configuration for
rollback. Its JSON response reports `connectivityTested: true`. Different credential bytes cannot
silently replace an existing secret identity; rotate with a new `--secret-id`. New Responses and
Anthropic primary/fallback commands enable their protocol-specific SSE by default. Add
`--disable-streaming` only for a compatible endpoint that implements its terminal JSON contract
but not SSE; legacy configuration without the `streaming` field remains terminal-only until
explicitly reconfigured. For a deliberately staged configuration on a host with no endpoint
access, `--skip-connectivity-test` is explicit and the
response records `connectivityTested: false`; run a tested reconfiguration before production use.

Start Mealy again without exporting the key into its service environment:

```sh
"$HOME/.local/bin/mealyd" --home "$HOME/.mealy"
```

The credential value is resolved from the private broker at startup, zeroized with the provider
object, omitted from configuration and durable requests, and never included in diagnostic output.
Remote endpoints must use HTTPS; plain HTTP is accepted only for literal loopback addresses.
Redirects and proxy environment variables are ignored at this trust boundary.

## Use governed memory from chat

`mealyctl chat` prints the memory namespace used by ordinary turns. It selects
`mealy://assistant/no-workspace` when no workspace tools are active and
`mealy://assistant/granted-workspaces` when they are. To retain one exact owner-entered fact as a
private, standard-retention memory with 8,000-basis-point confidence:

```text
/remember I prefer concise operational summaries with explicit blockers.
```

This is an explicit state-changing owner command, not text sent to the model. The client first
commits a proposed revision with a SHA-256 citation to the exact entered content, then sends a
separate bound owner-approval activation. The JSON response contains the logical `memoryId`, its
immutable `revisionId`, lifecycle revision, content digest, and source. If proposal succeeds but
activation fails, the error prints both durable IDs so the proposal can be inspected, activated,
rejected, or deleted instead of being silently lost.

Inspect and maintain memory without leaving the concurrent chat surface:

```text
/memories
/memories operational summaries
/history continuity marker
/memory-status MEMORY_ID
/memory-correct MEMORY_ID CURRENT_REVISION I prefer brief operational summaries with risks first.
/memory-expire MEMORY_ID CURRENT_REVISION
/memory-delete MEMORY_ID CURRENT_REVISION
```

`expire` removes an active memory from retrieval while retaining its audit content. `delete`
scrubs revision content and derived-index rows while retaining lifecycle/digest tombstones.
Correction preserves the current category, confidence, sensitivity, and retention, creates a new
cited revision, and atomically supersedes the old one. Optimistic revisions prevent a stale chat
command from overwriting concurrent owner changes. `/memory-reject MEMORY_ID CURRENT_REVISION`
rejects a proposal, and `/memory-activate MEMORY_ID REVISION_ID` explicitly activates a reviewed
proposal. Change only the local chat namespace with `/memory-use WORKSPACE`; this grants no new
workspace or model authority.

`/history QUERY` searches canonical user inputs and committed final-assistant text across sessions
owned by the exact local principal/channel binding. The scriptable form is:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" session search \
  "continuity marker" --limit 20
```

Search is a literal, case-insensitive substring match—`%` and `_` are not wildcards. Results are
newest first and contain stable session/turn/task IDs, at most 512 UTF-8 bytes around the match on
each side, and digests of the complete canonical content. The endpoint returns at most 100 turns
and rejects empty, untrimmed, control-bearing, or oversized queries. A local search cannot cross
into a Telegram, Discord, or webhook session even when the principal is the same, because channel binding is
filtered before content matching. Resume a hit with `chat --session-id SESSION_ID` and inspect its
task/timeline through the returned IDs.

The same concise workflow is scriptable outside the REPL:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" memory remember \
  --workspace mealy://assistant/no-workspace \
  "I prefer concise operational summaries with explicit blockers." \
  --approve
```

Advanced `memory propose`, `activate`, `correct`, `pin`, `expire`, `reject`, `delete`, `search`,
`list`, `export`, and `rebuild-index` commands expose exact category, confidence, sensitivity,
retention, authorization, and external source controls. Mealy never treats retrieved memory as
hidden instruction: active matches are injected as explicitly untrusted, owner-scoped evidence
with the memory/revision and source-digest citations recorded in the context manifest. The model
may suggest an exact `/remember TEXT` command for a useful non-sensitive fact, preference, goal,
decision, or constraint, but must label it as a suggestion and cannot claim it was saved. It is
explicitly instructed to route credentials, identity numbers, health, financial, and third-party
private content to the advanced categorized review workflow. The model never autonomously
activates memories; every activation remains an explicit authenticated owner action.

Use `mealyctl chat` or the lower-level session commands shown above. A real-provider turn makes one
bounded request, commits the normalized response and usage, runs deterministic integrity
validation, and supports recorded-only replay without another network call. Definite transient
responses use persisted jittered backoff. An ambiguous post-dispatch transport timeout is charged
as outcome-unknown and is never duplicated automatically. Streaming endpoints must return bounded
UTF-8 `text/event-stream` events for their configured protocol. Mealy caps the stream at 8 MiB and
text at 64 KiB and coalesces preview persistence to at most 256 events of at most 4 KiB each.
Responses requires streamed text to match the terminal `response.completed` object exactly;
Anthropic requires the ordered `message_start`, content-block, cumulative-usage `message_delta`,
and `message_stop` sequence with one unambiguous text or tool decision. A malformed, oversized,
truncated, ambiguous, or inconsistent stream cannot become the final answer. HTTP dispatch and body
reads poll durable cancellation every 50 ms and drop the live request on cancellation; because the
network boundary may already have been crossed, that path retains outcome-unknown accounting.
Both setup probes and live dispatch require the terminal response to name the exact configured
model; Responses also requires `object: "response"`. This is why the examples select exact
versioned IDs/slugs rather than moving aliases. Provider request IDs are retained only when bounded
and control-free, and provider-supplied incomplete/error detail is never copied into Mealy's local
error text.

To append an explicit fallback while the daemon is stopped, repeat the model-specific bounds and
price inputs with a distinct provider and secret identity:

```sh
export FALLBACK_API_KEY='replace-with-your-fallback-api-key'
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" config provider-fallback \
  --provider-id openai-fallback.responses \
  --model YOUR_FALLBACK_MODEL \
  --secret-id openai-fallback \
  --credential-env FALLBACK_API_KEY \
  --residency openai-api \
  --context-tokens YOUR_CONTEXT_LIMIT \
  --maximum-output-tokens YOUR_OUTPUT_LIMIT \
  --input-microunits-per-million-tokens YOUR_INPUT_PRICE \
  --output-microunits-per-million-tokens YOUR_OUTPUT_PRICE \
  --approve
unset FALLBACK_API_KEY
```

An Anthropic fallback uses the same bounds with its own wire command. The `--residency` value must
still exactly match the primary, so this example deliberately retains `openai-api` as the owner's
shared trust label rather than treating the vendor name as an enforcement boundary:

```sh
export ANTHROPIC_API_KEY='replace-with-your-fallback-api-key'
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" config provider-fallback-anthropic \
  --provider-id anthropic-fallback.messages \
  --model YOUR_EXACT_CLAUDE_MODEL_ID \
  --secret-id anthropic-fallback \
  --residency openai-api \
  --context-tokens YOUR_CONTEXT_LIMIT \
  --maximum-output-tokens YOUR_OUTPUT_LIMIT \
  --input-microunits-per-million-tokens YOUR_INPUT_PRICE \
  --output-microunits-per-million-tokens YOUR_OUTPUT_PRICE \
  --approve
unset ANTHROPIC_API_KEY
```

Fallback residency and locality must exactly match the primary; provider identities must be
unique; a chain may mix the two supported protocols without weakening either boundary. Every
retry is a new immutable attempt whose actual endpoint/model appears in the timeline and recorded
replay. `status` reports each endpoint's `protocol` and combines live health/concurrency/minute pressure with cumulative
durable dispatch counts and last success/failure times that survive daemon restart. `doctor` gives
a secret-free repair action for unprobed, rate-limited, degraded, and unhealthy endpoints.
`--safe-mode` deliberately resolves none of the external credentials or adapters.
Do not put keys in `config.json`, command-line arguments, or checked-in service units.

To rotate or retire one fallback without rebuilding the other entries, stop the daemon, remove
that exact provider identity, then append its reviewed replacement:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" config provider-list
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" \
  config provider-fallback-remove OLD_FALLBACK_PROVIDER_ID --approve
```

Removal preserves the remaining order and retains the old broker key. A new primary activation
also preserves compatible fallbacks; if its residency/locality or identity conflicts, activation
fails without discarding the chain. Revoke an old broker key only after the active config no
longer references it.

Rotate a model credential by first activating the provider with a new `--secret-id` and the new
upstream key. Compatible fallback entries remain ordered and active. Once the active config
no longer references the old identity, permanently remove its broker file while stopped:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" config provider-secret-revoke OLD_SECRET_ID --approve
```

The command rejects a secret still referenced anywhere in the active config, is idempotent when it
is already absent, and warns when archived configuration may still refer to it. Removing a broker
copy does not revoke the credential at the provider and does not erase immutable encrypted backups;
rotate or revoke upstream and apply the required backup-retention policy separately.

## Install and enable a data-only skill

A Mealy skill is a reviewed bundle of instructions and passive resources, not executable code or
ambient authority. Create a package directory whose complete file inventory contains exactly
`manifest.json` plus every declared asset. This abbreviated manifest shows the contract:

```json
{
  "contractVersion": "mealy.skill.v1",
  "skillId": "owner.release-review",
  "version": "1.0.0",
  "instructions": [{
    "relativePath": "instructions/review.md",
    "mediaType": "text/markdown",
    "contentDigest": "LOWERCASE_SHA256_OF_REVIEW_MD",
    "sizeBytes": 123
  }],
  "resources": [{
    "relativePath": "resources/rubric.json",
    "mediaType": "application/json",
    "contentDigest": "LOWERCASE_SHA256_OF_RUBRIC_JSON",
    "sizeBytes": 456
  }],
  "requiredTools": [{
    "toolId": "workspace.read",
    "version": "1",
    "inputSchemaDigest": "REVIEWED_TOOL_INPUT_SCHEMA_SHA256"
  }]
}
```

Use `sha256sum FILE` and `wc -c < FILE` to fill each exact asset record, then compute the exact
manifest digest. Inspection is read-only and does not require a running daemon:

```sh
SKILL_ROOT="$HOME/my-skills/release-review"
SKILL_DIGEST="$(sha256sum "$SKILL_ROOT/manifest.json" | cut -d ' ' -f 1)"
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" skill inspect \
  --manifest "$SKILL_ROOT/manifest.json" \
  --package-root "$SKILL_ROOT" \
  --digest "$SKILL_DIGEST"
```

Drain the daemon, install the reviewed bytes inertly, inspect the copied revision, and activate
that exact digest as a separate decision:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" drain
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" skill install \
  --manifest "$SKILL_ROOT/manifest.json" \
  --package-root "$SKILL_ROOT" \
  --digest "$SKILL_DIGEST" --approve
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" skill status owner.release-review
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" skill enable owner.release-review \
  --expected-manifest-digest "$SKILL_DIGEST" --approve
"$HOME/.local/bin/mealyd" --home "$HOME/.mealy"
```

Inspection rejects symlinks, traversal, undeclared files, missing assets, changed size/digest,
non-UTF-8 or control-bearing instructions, oversized inventories, and executable helper fields.
Installation copies the already-inspected bytes into an owner-private immutable digest directory
and records a home-relative reference. It is disabled initially. At startup, Mealy re-verifies all
installed packages and admits at most 16 enabled skills, 256 KiB of combined instructions, and
32 MiB of combined passive resources. A missing or changed installed byte fails startup closed.

Enabled instruction text enters a new context epoch with skill/version/manifest/asset digests and
an explicit lower-precedence boundary. Resource contents do not enter the baseline. Their names
and digests are advertised, and the separately declared `skill.read_resource` read-only tool can
return at most 64 KiB per call with a `skill://SKILL_ID/PATH` citation, byte counts, media type,
encoding, and complete-content digest. A manifest's `requiredTools` are reviewable references only:
they never grant workspace, web, process, secret, extension, or delegation authority and are usable
only if normal configuration/policy separately declares the exact tool.

An update is digest-fenced and always leaves the replacement disabled for another review/enable
decision; the prior immutable package remains available to configuration history and rollback:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" skill update owner.release-review \
  --expected-manifest-digest "$OLD_DIGEST" \
  --manifest "$NEW_SKILL_ROOT/manifest.json" \
  --package-root "$NEW_SKILL_ROOT" --digest "$NEW_DIGEST" --approve
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" skill enable owner.release-review \
  --expected-manifest-digest "$NEW_DIGEST" --approve
```

Disable without deleting evidence by draining and running `skill disable SKILL_ID
--expected-manifest-digest DIGEST --approve`. `skill list` and `skill status` re-verify installed
bytes and can be used read-only while the daemon is running. Complete exports, normal/encrypted
backups, isolated verification, activation, and cross-schema rollback preserve all referenced
skill package bytes.

## Add a local MCP stdio tool

The first MCP boundary is deliberately narrow: Linux only, native ELF stdio servers only, exact
MCP protocol revision `2025-11-25`, and read-only computation only. A server receives direct
non-secret arguments and model-proposed tool arguments, but no inherited environment, network,
Mealy home, host workspace, secret, shell, `PATH`, or writable persistent filesystem. Script and
interpreter entry points, HTTP MCP, OAuth, server credentials, host resource mounts, and effectful
tools are not supported yet.

First inspect an exact canonical executable. Inspection runs the code inside the same sandbox but
does not change agent authority or configuration:

```sh
MCP_SERVER="$(realpath "$HOME/bin/my-mcp-server")"
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" config mcp-inspect \
  localtools "$MCP_SERVER"
```

Use repeated `--argument VALUE` options only for public, non-secret server settings. Arguments are
stored in `config.json`; never put a token, password, private host path, or shell expression there.
The JSON response contains the negotiated server metadata, every paginated tool definition, each
definition digest, the complete tool-set digest, and the executable digest. Review the complete
definitions and schemas. Mealy does not trust MCP annotations such as `readOnlyHint` as an
authorization boundary.

Stop Mealy, select only the exact remote tool names you intend to expose, and approve the
installation:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" drain
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" config mcp-add \
  localtools "$MCP_SERVER" \
  --allow-tool calculate \
  --timeout-ms 30000 \
  --maximum-output-bytes 262144 \
  --approve
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" config mcp-list
"$HOME/.local/bin/mealyd" --home "$HOME/.mealy"
```

`mcp-add` independently discovers the server again, copies the reviewed bytes to
`mcp-servers/<EXECUTABLE_SHA256>/server` with owner-only permissions, and records the complete
tool-set pin plus each selected full definition. The model-visible name is
`mcp.localtools.calculate`. A normal chat turn can use it when useful; successful evidence carries
the citation `mcp://localtools/calculate`. `status` lists the enabled model-visible tool ID, and the
task timeline records its exact version, schema, policy, output digest, and locator.

Startup and every tool call launch a fresh process, negotiate the exact protocol, paginate the
complete `tools/list`, and compare it with the owner-reviewed pins before `tools/call`. Any missing,
extra, renamed, or changed advertised tool, schema, argument list, executable byte, or required
structured result fails closed. Input must satisfy the pinned self-contained object JSON Schema;
external schema resolution and required MCP task support are rejected. Calls have hard
wall-clock, message, stdout, stderr, normalized-output, CPU, address-space, file, descriptor, and
process limits. Cancellation sends the MCP cancellation notification and then terminates the
sandbox. Recorded-only task replay never starts the server and remains verifiable if its executable
is later unavailable.

Disable a problematic server while retaining its immutable executable and review evidence, or
re-enable it only after a fresh live tool-set check:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" drain
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" config mcp-disable localtools --approve
```

To reactivate it later, keep the daemon stopped and run
`config mcp-enable localtools --approve`; enable launches a fresh isolated discovery before it
writes configuration.

Use `config mcp-revoke localtools --approve` to remove it from active configuration. A changed
server is a new review: revoke the old entry, inspect the new bytes, and add the identity again.
Configuration history and the content-addressed executable are retained for rollback. Complete
exports, backups, isolated restore verification, activation, and cross-schema rollback copy and
re-verify every configured MCP executable. `--safe-mode` launches none of them. If one prevents a
normal startup, keep the daemon stopped, run `mcp-list`, disable or revoke that server, and restart.

## Grant a read-only workspace

Workspace authority is opt-in and changes only while the daemon is stopped. Grant an existing
directory under a stable logical identity:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" config workspace-grant \
  project "$(realpath "$HOME/src/my-project")" --approve
"$HOME/.local/bin/mealyd" --home "$HOME/.mealy"
```

The model sees `project` and relative paths, never the host root. It may use `workspace.list`,
`workspace.stat`, `workspace.read`, and `workspace.search`; results carry exact `workspace://`
locators, search hits include line locators, and grounded final answers must cite at least one
recorded locator. Reads, listings, traversal, output bytes, files, directories, entries, matches,
and execution time are bounded. Linux `openat2` enforces beneath-root, no-symlink, no-magic-link,
and no-mount-crossing resolution for every access. Startup fails closed if the canonical root is
missing, redirected, or cannot support that enforcement. Workspace tools are therefore currently
Linux-only even though conversation-only control-plane builds exist on other platforms.
The granted root must also be disjoint from the complete Mealy home: the home itself, any child of
it, and any parent containing it are rejected both by `mealyctl` and again at daemon startup. Do
not move private state beneath a configured workspace.

To revoke the authority, drain Mealy, update configuration, and restart:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" drain
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" config workspace-revoke project --approve
"$HOME/.local/bin/mealyd" --home "$HOME/.mealy"
```

The restart creates a new context epoch before the next model call. Previously recorded evidence
remains replayable, but prior conversation/memory/compaction material, revoked schemas, and the
workspace identity are absent from that request. Later turns carry only conversation created under
the replacement epoch.

## Enable governed mutations for one workspace

Write authority is separate from the read grant and remains disabled by default. With Mealy
stopped, enable it for one already-granted workspace and restart:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" config workspace-write-enable \
  project --approve
"$HOME/.local/bin/mealyd" --home "$HOME/.mealy"
```

The configuration response reports `restartRequired=true` and
`serviceReinstallRequired=false`. The Linux unit does not embed workspace paths; after changing a
grant, restart either the existing user service or the foreground daemon. Each governed operation
still mounts only its selected workspace into a fresh Bubblewrap sandbox.

In `mealyctl chat`, explicitly select action mode for one task:

```text
/act Create a new release note at notes/release.txt in the project workspace.
```

The model receives `workspace.create_file` only for that `/act` task. It must name a configured
writable workspace, a canonical relative path, and bounded UTF-8 content. Parent directories must
already exist. The worker uses create-new semantics with mode `0600`: an existing target,
traversal, symlink crossing, or missing/non-directory parent fails without replacement. Before
dispatch, the REPL displays an immutable approval subject binding the logical `workspace://`
target, exact arguments digest, worker digest, policy, task, effect, and expiry. Denial or expiry
causes no write. Approval launches one no-network/no-secret Bubblewrap worker; its terminal evidence
is recorded before the model may report success, and replay never dispatches it again.

To modify an existing file, use the distinct edit intent:

```text
/edit Replace the existing notes/release.txt content with the corrected release note.
```

Only that task receives `workspace.replace_file`. The model must first read the complete current
file and pass its exact SHA-256 as `expectedCurrentDigest`; the old file is limited to 128 KiB. It
may then propose exactly one of two approval-bound forms:

- complete new UTF-8 `content`, limited to 8,192 characters and 48 KiB; or
- one to 16 ordered `replacements`, each containing non-empty exact `oldText`, `newText`, and an
  `expectedOccurrences` value from 1 to 32. Each text side is limited to 8,192 characters, the
  aggregate patch input is bounded to 48 KiB, and the resulting file remains limited to 128 KiB.

For a small edit the agent is instructed to prefer the exact replacement form. Approval binds the
digest, complete canonical content or ordered edit list, expected counts, logical target, worker
identity, policy, and expiry. The sandbox reopens the existing regular target with Linux `openat2`
beneath/no-symlink/no-mount-crossing constraints, compares its digest, applies each exact edit in
order only when its non-overlapping match count equals the approved expectation, writes a private
mode-`0600` staging file, atomically renames, and synchronizes the workspace directory. A stale
digest, occurrence mismatch, invalid UTF-8, size overflow, absent/non-regular target, symlink,
traversal, or missing parent fails without changing the target. This is deterministic exact-text
patching, not fuzzy matching; obtain fresh evidence and approval after any concurrent change.

For one directory or file-path lifecycle operation, use the separate manage intent. Examples:

```text
/manage Create the archive/2026 directory in the project workspace.
/manage Move drafts/release.txt to archive/release.txt in the project workspace.
/manage Remove obsolete/release.txt from the project workspace.
/manage Remove the empty obsolete directory from the project workspace.
```

Only that task receives `workspace.manage_path`, and exactly one of four strict operation shapes is
accepted:

- `create_directory` creates one absent directory with mode `0700`; its parent must already exist;
- `move_file` moves one regular file of at most 128 KiB from an exact source to an absent
  destination after its complete current SHA-256 matches `expectedSourceDigest`;
- `remove_file` removes one regular file of at most 128 KiB only after its complete current SHA-256
  matches `expectedCurrentDigest`; or
- `remove_empty_directory` removes exactly one empty directory.

The agent is instructed to read the complete file before a move/removal and to list a directory
completely before requesting removal. Approval binds the operation, digest precondition when
applicable, worker/policy/expiry, and every logical target; a move displays both source and
destination. The Linux worker opens only safe parents beneath the selected root, never follows
symlinks or crosses mounts, uses `renameat2(RENAME_NOREPLACE)` for a move, and never recursively
creates or removes. File removal first moves the exact entry to a unique root-level quarantine,
synchronizes both directories, verifies its digest again, and only then unlinks it. Collisions,
stale evidence, missing parents, non-regular/oversized files, non-empty directories, traversal, and
symlinks fail closed without overwriting or deleting different bytes.

Lifecycle operations are conservatively non-idempotent and are never retried after an ambiguous
post-dispatch crash. Such an effect becomes `outcome_unknown`; inspect its effect/attempt and the
logical paths (including any `.mealy-remove-<effect>-<attempt>.quarantine` entry), then use the
authenticated reconciliation command described in [Operations](OPERATIONS.md). Recorded replay
never touches the filesystem.

`status` lists `workspace.create_file`, `workspace.manage_path`, and `workspace.replace_file` under
`enabledActionTools`.
Remove only write authority while
retaining reads by draining, disabling, and restarting:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" drain
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" config workspace-write-disable \
  project --approve
"$HOME/.local/bin/mealyd" --home "$HOME/.mealy"
```

`--safe-mode` exposes no action tool. Recursive directory creation/removal, directory moves,
overwriting moves, chmod, and a managed background-process lifecycle are not implemented yet.

## Enable one direct installed command

Direct-process authority is separate from workspace write authority. It is high risk: the selected
program can perform any operation its own code and the writable workspace permit. Grant only a
reviewed command whose semantics and proposed argv you understand. With the daemon stopped and at
least one writable workspace configured:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" config process-grant \
  mkdir /usr/bin/mkdir --approve
"$HOME/.local/bin/mealyd" --home "$HOME/.mealy"
```

The grant accepts only a canonical root-owned executable whose file and complete parent-directory
chain are not group/world writable. It records the executable's SHA-256 identity. Startup and every
selected dispatch re-check that identity. In chat, select the capability for one task:

```text
/run Use the configured mkdir command to create reports/2026 in the project workspace.
```

The model receives `process.run` plus read tools only for that task. Mealy invokes the selected
executable directly—there is no implicit shell or `PATH` lookup—and mounts no other configured
command into that attempt. It supplies an empty environment and null stdin, no network or secret
handles, one selected writable workspace, at most 32 bounded arguments, 10 seconds, 16 child
processes, and bounded stdout/stderr. The approval preview shows the logical
`command://<id>@sha256:<digest>` identity, workspace/working directory, and exact normalized argv.

Do not grant a shell or interpreter unless you deliberately accept its broader semantics. A
non-idempotent process is never automatically retried after dispatch; an outcome-unknown attempt
parks for explicit inspection and `effect reconcile`. Revoke a command while stopped:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" drain
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" config process-revoke mkdir --approve
"$HOME/.local/bin/mealyd" --home "$HOME/.mealy"
```

## Enable bounded web search and fetch

Web authority is disabled by default and changes only while the daemon is stopped. This example
enables public HTTPS fetches plus Brave Search, importing the search token once:

```sh
export BRAVE_SEARCH_API_KEY='replace-with-your-Brave-Search-token'
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" config web-enable \
  --allow-public-internet \
  --brave-secret-id brave-search \
  --approve
unset BRAVE_SEARCH_API_KEY
"$HOME/.local/bin/mealyd" --home "$HOME/.mealy"
```

Use repeated `--allow-domain example.com` flags instead of `--allow-public-internet` when a
specific public DNS suffix is sufficient. Exact canonical origins can be granted with
`--allow-origin`; plain HTTP is accepted only for an explicitly granted literal-loopback origin.
Search is omitted when `--brave-secret-id` is absent, leaving only fetch authority.

`web.fetch` and `web.search` ignore proxy variables, send no model credential, reject redirects,
pin validated DNS results to the connection, reject any private/reserved/mixed DNS answer, verify
the connected peer, enforce status/content-type/time/byte/result bounds, and treat returned text
as untrusted evidence. IPv6 destinations additionally fail closed outside the reviewed current
IANA global-allocation table. HTML comments, scripts, styles, and noscript blocks are removed before
context use; tag parsing respects quoted delimiters and entity decoding is single-pass.
Tool results carry exact URL or `search://` provenance; evidence-backed final answers must cite a
recorded source locator. Search credentials remain only in the private broker and are never placed
in model requests, tool evidence, timelines, config, or diagnostics.

Disable all web schemas and outbound authority with:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" drain
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" config web-disable --approve
```

Disable retains the brokered token so a digest-pinned configuration rollback remains operable.
A dedicated broker-token erase/rotation command is not exposed yet; revoke the token at Brave if
immediate external invalidation is required.

## Enable the isolated rendered browser

The first browser boundary is Linux x86_64 only and deliberately read-only. It never attaches to
your normal Chrome profile. Web authority must already be enabled as shown above; the browser uses
that exact destination ceiling rather than creating a second network allowlist.

Fetch the repository-pinned Chrome Headless Shell bundle with the managed helper. An archive
installation puts it below the per-user metadata directory; the Debian package installs the same
checksummed helper below its package-owned release directory. A source checkout uses the repository
script instead:

```sh
# Archive installation:
FETCH_BROWSER="$HOME/.local/share/mealy/fetch-browser-runtime.sh"
MEALYCTL="$HOME/.local/bin/mealyctl"
MEALYD="$HOME/.local/bin/mealyd"
# Debian package installation instead:
# FETCH_BROWSER="/usr/lib/mealy/release/fetch-browser-runtime.sh"
# MEALYCTL="/usr/bin/mealyctl"
# MEALYD="/usr/bin/mealyd"
# Source checkout instead:
# FETCH_BROWSER="$PWD/scripts/fetch-browser-runtime.sh"
# MEALYCTL="$PWD/target/release/mealyctl"
# MEALYD="$PWD/target/release/mealyd"

BROWSER_BUNDLE="$("$FETCH_BROWSER" "$HOME/.cache/mealy/browser-runtimes")"
"$MEALYCTL" --home "$HOME/.mealy" config browser-inspect "$BROWSER_BUNDLE"
```

The helper currently pins Chrome for Testing Headless Shell `151.0.7922.34`, archive size
`120231126`, and SHA-256
`3cfc2bd00d1bafcf8a68dc74c9c92bb7150ddc8d26ade948a776316e1cec4f14`. It uses HTTPS, rejects an
unexpected redirect protocol/count, connection or total-time overrun, transfer size, archive
path/type/count, and never silently selects “latest.” `browser-inspect` then
performs complete no-symlink bundle inspection and executes only `--version` in a no-network,
no-home Bubblewrap namespace. Review the returned bundle/executable digests, product
`HeadlessChrome/151.0.7922.34`, and CDP `1.3` identity.

Drain the daemon, install the exact bytes, and approve model-visible authority:

```sh
"$MEALYCTL" --home "$HOME/.mealy" drain
"$MEALYCTL" --home "$HOME/.mealy" config browser-add \
  "$BROWSER_BUNDLE" --approve
"$MEALYCTL" --home "$HOME/.mealy" config browser-list
"$MEALYD" --home "$HOME/.mealy"
```

In `mealyctl chat`, ask Mealy to render an authorized URL and, when needed, activate an exact
accessible button or fill an exact text/search field by its displayed name. The model can select
`activateElement` only for a native, enabled, form-free `type=button`; an absent, ambiguous,
disabled, submit, or form-owned target fails closed. `fillElement` accepts only an accessible
`textbox` or `searchbox` backed by an enabled writable native text/search/email/URL/telephone input
or textarea—never password, file, hidden, disabled, or read-only controls. `submitGetForm: true`
does not invoke the page form: Mealy validates its method/action/target, then constructs a
same-origin GET from only the selected non-empty control name and exact value. Hidden and sibling
fields are not sent. Every call starts from the supplied URL in a new profile, so it cannot continue
login or cookie state from an earlier call.

`downloadLink` selects one exact accessible same-origin link by name and occurrence. Chrome remains
download-denied for every other operation; for this one request Mealy uses `allowAndName` in an
ephemeral profile directory, requires bounded CDP begin/progress/completion evidence, validates the
GUID filename, opens it with `NOFOLLOW`, and admits at most 512 KiB. The result contains
`application/octet-stream` base64, size, SHA-256, and exact URL inside the normal durable tool
artifact. It never chooses or writes an owner filesystem path.

`browser-add` copies the complete reviewed bundle to
`browser-runtimes/<BUNDLE_SHA256>`, then runs a real end-to-end verification through a temporary
exact loopback origin before writing configuration. Startup re-verifies the complete bundle. Each
`browser.snapshot` call launches a new Headless Shell process with an ephemeral profile, empty
environment, private network namespace, no home/workspace/secret mounts, no host CDP listener, and
hard process/CPU/file/output/time bounds. The only egress is a private Unix-socket proxy that
re-resolves and pins configured destinations, limits aggregate traffic, accepts only GET/HEAD, and
caps each of its two relay layers at 32 concurrent and 256 total connections per call while promptly
reclaiming completed handlers. A
call narrows that configured ceiling further to the exact origin of its initial URL: cross-origin
redirects, subresources, and followed or activated links are denied even if their origins are separately present
in web configuration. This is intentionally strict and means pages that require a CDN or another
origin may render only their same-origin content.
CDP rejects other methods and authentication, denies ambient downloads, blocks WebSocket/WebTransport and
direct sockets, and exposes only normalized accessibility text/elements, URL/title, and an
optional PNG of at most 512 KiB. A call can follow one exact accessible link by name and occurrence;
that is implemented as another direct same-origin GET navigation. Alternatively it can activate
one exact accessible native `<button type="button">` that is enabled and not owned by a form. The
worker uses a pristine click method captured before page code; submit controls and form buttons are
rejected. Exact text filling similarly uses pristine native value setters and dispatches no
input/change/submit events. Optional GET submission is constructed and authorized in the worker,
not delegated to page script, and any request still must be same-origin GET/HEAD. This is not
general clicking or arbitrary form automation.

The browser does **not** dispatch keyboard/input/change events, submit POST or multi-control forms,
upload files, choose owner download paths, capture more than one/512-KiB attachment, retain cookies,
expose raw DOM/CDP, or use a personal profile. Arbitrary or effectful interaction requires a future
approval contract and must not be inferred from `browser.snapshot`. Recorded task replay uses
stored evidence and never launches Chrome, even if the installed runtime was later removed.

Run browser-enabled production deployments through the installed systemd user service (or an
equivalent cgroup). Its unit applies `MemoryHigh=1G`, `MemoryMax=1536M`, zero swap, and a task cap to
the daemon and all browser children. V8 reserves a very large virtual address range, so
`RLIMIT_AS` cannot safely enforce RSS; a directly launched daemon has the other hard bounds but no
equivalent service-level physical-memory ceiling.

Disable or revoke while stopped:

```sh
"$MEALYCTL" --home "$HOME/.mealy" config browser-disable --approve
"$MEALYCTL" --home "$HOME/.mealy" config browser-enable --approve
"$MEALYCTL" --home "$HOME/.mealy" config browser-revoke --approve
```

Re-enable repeats the full bundle/product/CDP/rendering verification. Disable and revoke preserve
immutable runtime bytes for configuration rollback. `web-disable` is rejected while the browser is
enabled; disable/revoke the browser first. Safe mode never launches it. Complete backups, isolated
restore verification, activation, and cross-schema rollback preserve and re-verify the referenced
bundle.

## Connect a Telegram bot

Create a bot with Telegram's official [BotFather](https://t.me/BotFather) and keep its token private.
Do not paste the token into browser history, shell arguments, issue reports, or configuration.
With the normal (not safe-mode) daemon running, import the token from a one-shot environment
variable and start guided pairing:

```sh
export TELEGRAM_BOT_TOKEN='replace-with-the-BotFather-token'
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" channel telegram-pair
unset TELEGRAM_BOT_TOKEN
```

The CLI verifies the bot with bounded `getMe`, prints an exact high-entropy `/pair MEALY-...`
command, and waits at most 120 seconds by default. Send that command unchanged to the named bot in
a one-to-one private chat; group chats, bot-authored messages, edited codes, and expired codes do
not pair. The timeout can be set from 30 through 300 seconds with `--timeout-seconds`. Do not send a
real agent prompt until the command returns successfully. Pairing consumes the pre-pair backlog and
creates the durable cursor immediately after the accepted challenge, so `/start`, rejected pairing
attempts, and older messages cannot later become prompts.

Setup stores the token only in the owner-private credential broker and returns a `bindingId` plus a
dedicated `sessionId`.
SQLite, `config.json`, status, logs, and CLI JSON never contain the token. Mealy uses Bot API long
polling; remove any webhook configured for this bot first or status will report
`telegram_webhook_conflict`. Proxy environment variables and redirects are ignored.

For a self-hosted Bot API test endpoint, both daemon and pairing command must use the same validated
origin (`mealyd --telegram-api-base-url ORIGIN` and `telegram-pair --api-base-url ORIGIN`). Plain
HTTP is accepted only for a literal loopback IP. Advanced operators who have independently verified
the IDs can use `channel telegram-create --user-id USER_ID --chat-id CHAT_ID`; this manual path
starts at cursor zero and is not the recommended onboarding flow.

Ordinary bot messages use FIFO queueing. These exact controls are also available:

```text
/queue Add this after the current work.
/steer Use this fact at the next safe boundary.
/interrupt Stop at a safe boundary and do this instead.
```

When a governed action needs approval, the bot renders the exact tool, targets, normalized
arguments, immutable subject digest, and commands of the following form:

```text
/approve APPROVAL_ID SUBJECT_DIGEST
/deny APPROVAL_ID SUBJECT_DIGEST
```

Do not edit either identity. A stale, wrong-owner, expired, or digest-mismatched command cannot
authorize the effect. Text documents are accepted only as `text/plain`, `text/markdown`,
`text/csv`, or `application/json`, at most 256 KiB, with verified size, media type, UTF-8 content,
safe Telegram file path, and a SHA-256 label. Images, audio, video, archives, malformed text, and
oversized files are durably ignored; they do not become model input. Bot-authored messages and any
other sender/chat are also ignored.

Inspect health, the durable cursor, and lifecycle without exposing credentials:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" channel telegram-list
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" channel telegram-status BINDING_ID
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" status
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" doctor
```

Definite Bot API delivery failures retry through the durable outbox. If the connection fails after
`sendMessage` may have reached Telegram, Mealy terminally parks that delivery instead of risking a
duplicate; inspect outbox/recent failure evidence locally. Outbound text is capped at Telegram's
4,096-character limit with an explicit truncation marker, while the complete result remains in
the session timeline.

Revocation is terminal and removes the brokered token before returning:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" channel telegram-revoke BINDING_ID \
  --expected-revision REVISION
```

To rotate, revoke the binding, rotate the bot token with BotFather, and create a new binding. A
token digest that has owned a durable polling cursor cannot be silently reused for another
binding. Encrypted secret backups include active Telegram tokens only when `--include-secrets` is
explicitly selected.

## Connect a Discord bot to one direct message

Create an application and bot in the [Discord Developer Portal](https://discord.com/developers/applications),
keep the bot token private, and invite the bot to a server you control so you can open a direct
message with it. Enable Discord client Developer Mode, open the one-to-one bot DM, and copy that
DM's channel ID. Do not use a guild text channel, group DM, thread, or another person's DM: the
initial adapter accepts only Discord channel type `1` with exactly one non-bot recipient.

Start the normal daemon, then pair from a one-shot environment variable:

```sh
export DISCORD_BOT_TOKEN='replace-with-the-Developer-Portal-bot-token'
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" channel discord-pair \
  --channel-id DM_CHANNEL_ID
unset DISCORD_BOT_TOKEN
```

The CLI calls Discord API v10 to verify the current token is a bot, verifies the exact DM and
human recipient, samples the latest message as a setup fence, prints a random 128-bit
`/pair MEALY-...` command, and waits 120 seconds by default. Send that command unchanged from the
human account in that exact DM. The allowed timeout is 30–300 seconds. Do not send an agent prompt
until the command returns a `bindingId` and dedicated `sessionId`; setup samples the latest message
again before activation so setup traffic cannot become a later prompt. Operators who have already
verified both snowflakes may use the less friendly manual form:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" channel discord-create \
  --user-id USER_ID --channel-id DM_CHANNEL_ID
```

Mealy sends the token only in the `Authorization: Bot …` header, brokers it under
`provider-secrets/discord.BINDING_ID.key`, and stores only a digest pin and opaque secret identity
in SQLite. The default endpoint is the exact official `https://discord.com/api/v10`; an override
is accepted only for literal-loopback HTTP test servers, which prevents a configuration typo from
forwarding the token to an arbitrary HTTPS host. Proxies and redirects are disabled.

Ordinary text queues work. The exact `/queue`, `/steer`, `/interrupt`, `/approve`, and `/deny`
forms shown in the Telegram section work identically in the Discord DM. Discord message content in
a DM with the app is one of the platform's documented exceptions to the privileged
`MESSAGE_CONTENT` restriction ([Discord Gateway documentation](https://docs.discord.com/developers/events/gateway#message-content-intent)),
so the DM-only profile does not require guild message-content authority. Attachments, embeds-only
messages, webhooks, system message types, bot-authored output, another sender, and another channel
are durably ignored and never become model input. Use Telegram when bounded text-document input is
required; Discord attachment ingestion is intentionally not part of this first profile.

Inspect and revoke the binding without revealing the token:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" channel discord-list
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" channel discord-status BINDING_ID
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" channel discord-revoke BINDING_ID \
  --expected-revision REVISION
```

Inbound history uses Discord's documented newest-to-oldest, 1–100-message REST contract
([Get Channel Messages](https://docs.discord.com/developers/resources/message#get-channel-messages)).
Snowflakes remain canonical decimal strings instead of being narrowed to signed integers. A full
page is walked backward to the durable floor and deduplicated before any cursor advancement; the
bounded scan fails closed with `discord_backlog_exceeded` rather than skipping a gap. Every
message is reserved before admission and its terminal admitted/ignored receipt advances the
cursor in the same SQLite transaction, so hard restart replays the same idempotent boundary.

Outbound text follows Discord's 2,000-character limit, sends `allowed_mentions: {"parse":[]}` and
suppresses embeds, and uses a deterministic 25-character nonce with `enforce_nonce: true`. Discord
documents that this returns the prior message instead of creating another when the same author and
nonce recur within its uniqueness window ([Create Message](https://docs.discord.com/developers/resources/message#create-message)).
Mealy nevertheless parks ambiguous transport, server, or malformed-success outcomes instead of
risking a duplicate. Definite 429 responses retry only after Discord's `Retry-After`/`retry_after`,
which the platform requires clients to honor
([rate-limit documentation](https://docs.discord.com/developers/topics/rate-limits)). The full
result always remains in the local session timeline if a 2,000-character notification is
truncated. Rotate by revoking, resetting the token in the Developer Portal, and pairing a new
binding. Secret-bearing backups include the token only with explicit `--include-secrets`.

## Create a recurring schedule

Schedules target an existing durable session. This example admits one normal read-only turn at
09:00 on weekdays in Auckland time:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" schedule create SESSION_ID \
  --name "weekday brief" \
  --cron "0 9 * * MON-FRI" \
  --timezone Pacific/Auckland \
  --missed-run-policy latest \
  --overlap-policy skip-if-running \
  "Prepare my concise weekday brief."
```

Mealy accepts canonical five-field cron expressions, so the minimum interval is one minute. The
IANA time-zone identity controls daylight-saving behavior. `latest` coalesces downtime and fires
only the latest missed occurrence after restart; `skip` fires only when the latest occurrence is
within `--misfire-grace-ms`. `queue` uses the session's bounded FIFO, while `skip-if-running`
records a skipped occurrence if earlier work from the same schedule remains pending or active.
Mealy never emits unbounded catch-up work.

Inspect and control the definition using the current revision returned by `status`:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" schedule list
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" schedule status SCHEDULE_ID
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" schedule runs SCHEDULE_ID --limit 20
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" schedule pause SCHEDULE_ID --expected-revision REVISION
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" schedule resume SCHEDULE_ID --expected-revision REVISION
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" schedule cancel SCHEDULE_ID --expected-revision REVISION
```

Definitions are immutable; cancel and create a replacement to change the prompt or policy.
Cancellation is terminal and retains occurrence history. A prompt beginning `/act`, `/edit`,
`/manage`, or `/run` is rejected unless creation includes
`--allow-approval-required-action`; that flag does not
pre-approve an effect, and every resulting action still waits for its ordinary exact owner
approval. Safe mode starts no schedule driver and rejects schedule mutations. To deliver remotely,
pass the `sessionId` returned by `telegram-pair`/`telegram-create` or
`discord-pair`/`discord-create`; the scheduled prompt is admitted to that dedicated session and
its progress, approval request, and final result use the same durable channel outbox route.

## Delegate one bounded read-only task

Configured external-provider profiles expose `agent.delegate` to the model automatically. Ask for
an independent, self-contained assessment when delegation is useful; there is no slash command
that bypasses the model/tool policy:

```text
Delegate an independent review of this plan. Give the child explicit instructions and two concrete
success criteria, then incorporate its result.
```

The parent may launch at most the configured `agentLoopLimits.maximumDelegatedRuns` (two by
default), one at a time. Launch, child graph creation, budget reservation, and parent parking are
one transaction. The child receives only the explicit work package—not parent conversation,
memory, approvals, mutation tools, process authority, or further delegation. It may inherit the
parent's currently configured workspace/web/skill read tools, bounded by a maximum of three model
calls, two tool calls, 16,384 input tokens, 2,048 output tokens, 250,000 provider microunits, 1 MiB
of durable output, and 90 seconds; every child limit is also capped by the parent's configured
run ceiling.

Inspect the durable graph without trusting the model's prose:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" delegation list --limit 20
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" delegation status DELEGATION_ID
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" task status CHILD_TASK_ID
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" task replay CHILD_TASK_ID
```

Successful, failed, and cancelled child results return through the recorded
`delegation://result` tool observation before the parent continues. Cancelling the parent while it
waits propagates to a queued or running child, settles both reservations, and terminally cancels
the parent. Delegation is unavailable in the built-in offline fixture profile and in safe mode.

## Install as a user service

With `mealyd` and `mealyctl` installed beside each other in `$HOME/.local/bin`:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" service install
```

The command writes an owner-level systemd user unit on Linux and prints the exact activation
command. Review the emitted path and command before running it. The service references
the canonical daemon path, so do not install it from an expendable Cargo target directory. On
Linux the JSON response lists `readWritePaths`: the private Mealy home plus only the
currently configured writable workspaces. Re-run this command after every workspace grant,
write-enable, write-disable, or revoke before restarting the unit. The generated unit uses a
private `/tmp`/`/var/tmp` namespace, so installation rejects a home or workspace below either host
temporary hierarchy; it also rejects a home backed by `tmpfs` or `ramfs`. Keep durable state on a
local persistent filesystem. A custom `--destination` must still be named `mealy.service`; the
printed activation command links that exact absolute unit before enabling it.

## Stop safely

Close admission and drain all bounded workers:

```sh
"$HOME/.local/bin/mealyctl" --home "$HOME/.mealy" drain
```

Do not delete or copy a live home. Use `backup`, `restore-verify`, and `export complete` from the
operations guide for durable data movement.
Ordinary local API commands fail after 30 seconds instead of hanging indefinitely. Drain, backup,
restore verification, artifact garbage collection, and export use a separate ten-minute ceiling
because they may scan or synchronize durable state. Timeline watching is different: it keeps the
SSE connection open and reconnects from the last verified durable cursor after interruption.

## Next steps

- [`OPERATIONS.md`](OPERATIONS.md) covers safe mode, task control, backup, restore verification,
  export, retention, garbage collection, configuration rollback, migration, and forensics.
- [`REQUIREMENTS_COVERAGE.md`](REQUIREMENTS_COVERAGE.md) maps release-one invariants to executable
  evidence.
- [`TESTING.md`](TESTING.md) documents the local and CI gates.
