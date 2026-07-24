# Product operations benchmark: Mealy and the reference agent systems

Status: research baseline for the post-v0.1.1 onboarding work

Observed: 2026-07-24 (Pacific/Auckland)

Scope: installation, first useful run, provider/authentication setup, daily user
experience, updates and recovery, documentation maintenance, CI, and release
publication

Implementation note: post-v0.1.1 source now contains the P1 and P2 slices
recommended below: `mealyctl onboard`, a short `GETTING_STARTED.md`, strict
free-OpenRouter selection, integrated custom/local/subscription/API routes,
service start/health/doctor composition, installed-package process tests,
complete install-provenance/integrity status, attested no-mutation update
checks, same-schema archive apply, bounded stable-manager repair, archive
rollback/uninstall delegation, native APT/DNF/Pacman handoffs, and
Bash/Zsh/Fish completion. The researched OpenClaw/Hermes recovery pattern is a
separately supervised, durably phased update helper with pre-update backup,
drain/stop/start, health/doctor/version/integrity qualification, and automatic
same-schema slot rollback. Package-manager-native signed APT, DNF, and Pacman
repositories are built from the exact qualified artifacts, attested as a
complete manifest, deployed through protected Pages, and subject to clean
public HTTPS installation on native x86-64 and ARM64 runners. The verified
release bootstrap now also follows the observed installer pattern: a fresh
interactive install enters the exact installed onboarding client automatically,
with explicit force/passive controls and existing-home preservation. After
service and `doctor` qualification, terminal onboarding opens the first durable
chat; non-interactive callers retain bounded JSON and one exact next command.

This is not a retroactive change to the matrix observed before implementation.
It does not yet equal the complete competitor delivery experience:
an owner-controlled production signing identity and a published qualifying tag
remain external gates.
Exact generated-service removal is now plan-first and composed into owner-local
uninstall. Installed two-release failure injection now activates a checksum-valid
but deliberately unready newer package under the real owner service, proves the
preserved old helper verifies candidate bytes without executing its broken
client, and requires automatic rollback plus health, `doctor`, backup, and
durable-task preservation. All newer work remains next-release source until
protected installed-package and supported-distribution acceptance qualify it.

## Executive result

Mealy's runtime and release controls are unusually strong for a pre-1.0 agent,
but its user journey is not yet competitive with the easiest end-user
harnesses.

The largest gap is not core agent capability. It is orchestration:

1. a new user must understand too many implementation details before the first
   prompt;
2. model discovery, subscription authentication, custom endpoints, setup,
   service installation, daemon activation, diagnostics, and chat exist as
   separate expert commands;
3. the installer verifies a release well but stops before a working service;
4. update, repair, uninstall, and shell-completion experiences are incomplete;
5. the README and quickstart are comprehensive references, not a short first
   five-minute path; and
6. no stable Mealy release has been published yet.

OpenClaw, Hermes, OpenCode, Codex, Pi, and Claude Code all make the first useful
conversation the organizing product outcome. Vercel AI SDK and Eve are
framework comparators rather than equivalent downloadable assistants, but
their documentation, scaffolding, migration, and packed-artifact tests supply
useful maintenance patterns.

The recommended first product slice is a single guided `mealyctl onboard`
journey which reuses Mealy's existing governed primitives. It should discover
eligible models, make free OpenRouter and owner-local subscription paths
first-class, configure custom OpenAI-compatible endpoints, install and start
the owner service with explicit approval, wait for health, run `doctor`, and
then open chat. This work belongs to the release after v0.1.1: changing the
v0.1.1 candidate would invalidate its exact-binary 24-hour soak.

## Method

This is a fresh product-operations audit, not a restatement of the architecture
survey in [REFERENCE_SYSTEMS.md](REFERENCE_SYSTEMS.md).

For each system, the audit inspected:

- the current upstream default-branch commit;
- official install, quickstart, authentication, configuration,
  troubleshooting, update, rollback, and uninstall material;
- the actual CLI or scaffold implementation where public source was available;
- public CI and release workflows at the observed commit;
- the latest ten public GitHub releases; and
- whether install, first-run, package, update, and release claims are backed by
  tests or workflow evidence.

The comparison distinguishes:

- **end-user harnesses**: OpenClaw, Hermes, OpenCode, Codex, Pi, Claude Code;
- **framework comparators**: Vercel AI SDK and Eve; and
- **observational-only material**: the unlicensed third-party Claude Code source
  mirror used by the original architecture survey.

Public repositories cannot reveal private release infrastructure. An absent
public workflow therefore means “not publicly evidenced,” not “does not
exist.” Documentation and code inspection also do not replace independent live
provider acceptance.

## Reproducible source ledger

| System | Upstream commit observed | Classification | Current public release signal |
|---|---|---|---|
| [OpenClaw](https://github.com/openclaw/openclaw/tree/4f4d89574a9e1361344f1435c994d30e15a166cf) | `4f4d89574a9e1361344f1435c994d30e15a166cf` | End-user harness | Stable `v2026.7.1` on 2026-07-13; later beta releases through 2026-07-18 |
| [Hermes Agent](https://github.com/NousResearch/hermes-agent/tree/781968be5e1ec2c253b617409f8bfba652c10186) | `781968be5e1ec2c253b617409f8bfba652c10186` | End-user harness | `v2026.7.20` on 2026-07-20 |
| [OpenCode](https://github.com/anomalyco/opencode/tree/62e4641235d7847dadc60da37cca8a023dd54fc1) | `62e4641235d7847dadc60da37cca8a023dd54fc1` | End-user harness | `v1.18.4` on 2026-07-20; five stable releases in the preceding week |
| [Codex](https://github.com/openai/codex/tree/7d748d3bbcbd640988813de962455f27c918abdf) | `7d748d3bbcbd640988813de962455f27c918abdf` | End-user harness | Stable `rust-v0.145.0` on 2026-07-21 plus frequent alpha builds |
| [Vercel AI SDK](https://github.com/vercel/ai/tree/1f6dd3a804743555a1f5e1f066ba3e097e5392c6) | `1f6dd3a804743555a1f5e1f066ba3e097e5392c6` | Framework comparator | `ai@7.0.36` and coordinated package releases on 2026-07-23 |
| [Eve](https://github.com/vercel/eve/tree/876bf3d7afc9029809fbb5ce27a2a2ebbaf6db11) | `876bf3d7afc9029809fbb5ce27a2a2ebbaf6db11` | Framework comparator | `eve@0.27.1` on 2026-07-22; ten releases in the preceding week |
| [Pi](https://github.com/earendil-works/pi/tree/65ff8e7f6db447dcddb1a9c8fd05f081c5cda76a) | `65ff8e7f6db447dcddb1a9c8fd05f081c5cda76a` | End-user harness/toolkit | `v0.81.1` on 2026-07-21 |
| [Claude Code](https://github.com/anthropics/claude-code/tree/2982f951552e94f38cd972764ae94c1d90c41da3) | `2982f951552e94f38cd972764ae94c1d90c41da3` | End-user harness; public repo is not the complete product source | `v2.1.218` on 2026-07-22; near-daily public releases |

Release dates were read from each repository's public GitHub Releases API on
the observation date. They indicate active maintenance, not release quality by
themselves.

The original unlicensed mirror remains pinned at
`a371abbe75ffa0d0a3c92290e2bbf56a7ef54367`. Its own README calls it a backup
of proprietary source recovered from a published source map. It has no product
release history and no build/test/release workflow. It is excluded from all
maintenance, documentation, distribution, and licensing recommendations.

## What users actually experience

### OpenClaw

Evidence:

- [installer reference](https://github.com/openclaw/openclaw/blob/4f4d89574a9e1361344f1435c994d30e15a166cf/docs/install/installer.md)
- [onboarding CLI](https://github.com/openclaw/openclaw/blob/4f4d89574a9e1361344f1435c994d30e15a166cf/docs/cli/onboard.md)
- [update CLI](https://github.com/openclaw/openclaw/blob/4f4d89574a9e1361344f1435c994d30e15a166cf/docs/cli/update.md)
- [doctor CLI](https://github.com/openclaw/openclaw/blob/4f4d89574a9e1361344f1435c994d30e15a166cf/docs/cli/doctor.md)
- [full release validation](https://github.com/openclaw/openclaw/blob/4f4d89574a9e1361344f1435c994d30e15a166cf/docs/reference/full-release-validation.md)

The hosted installer ensures its runtime and Git, installs the product, and
launches onboarding for a fresh user. Onboarding offers quickstart, manual, and
import flows; detects possible authentication routes; live-tests a provider
before persisting it; configures the daemon; and ends at a usable chat or
dashboard. Non-interactive and JSON flows support automation.

Maintenance is treated as a product surface. `openclaw update` understands
stable, extended-stable, beta, and development channels, stages a candidate
before swapping it, restarts the managed service, and verifies health and
version. `update repair` and `doctor` repair state/plugin convergence and handle
post-upgrade migrations.

The public workflows validate far more than unit tests: installer smoke,
website-installer synchronization, Linux/macOS/Windows behavior, UI and mobile
lanes, package acceptance, Docker, full release validation, and live channel
acceptance. The cost is a very large and complex maintenance surface.

**Lesson for Mealy:** make “working conversation after verified install” one
tested journey, but retain Mealy's smaller Linux-only scope and stricter
artifact identity.

### Hermes Agent

Evidence:

- [installation](https://github.com/NousResearch/hermes-agent/blob/781968be5e1ec2c253b617409f8bfba652c10186/website/docs/getting-started/installation.md)
- [quickstart](https://github.com/NousResearch/hermes-agent/blob/781968be5e1ec2c253b617409f8bfba652c10186/website/docs/getting-started/quickstart.md)
- [updates and uninstall](https://github.com/NousResearch/hermes-agent/blob/781968be5e1ec2c253b617409f8bfba652c10186/website/docs/getting-started/updating.md)
- [CLI reference](https://github.com/NousResearch/hermes-agent/blob/781968be5e1ec2c253b617409f8bfba652c10186/website/docs/reference/cli-commands.md)
- [CI orchestrator](https://github.com/NousResearch/hermes-agent/blob/781968be5e1ec2c253b617409f8bfba652c10186/.github/workflows/ci.yml)

The command-line installer handles Python through `uv`, Node, ripgrep, ffmpeg,
the checkout, an isolated environment, the global launcher, and provider
configuration. `hermes`, `hermes setup`, `hermes model`, and
`hermes setup --portal` keep setup inside the product. Guided choices include
API keys, subscriptions, OAuth providers, custom endpoints, local providers,
and a deliberately minimal “blank slate.”

Hermes has the strongest publicly documented recovery-oriented update UX in
this set. `hermes update` detects the install method, takes a pre-update state
snapshot, pulls, syntax-checks critical startup files, automatically rolls back
an unbootable pull, updates dependencies, migrates configuration, and restarts
gateways. It supports check-only mode, full backup, alternate branches,
disconnect-resistant logging, rollback instructions, `doctor`, and uninstall.

Its Docusaurus documentation has separate learning paths, task guides,
reference pages, platform support, FAQ, and provider catalogs. CI is
path-classified and aggregated behind one required gate; public lanes include
Python, JavaScript, desktop visual E2E, docs builds, Docker, OSV, lockfile, and
supply-chain review.

The release script is less controlled than Mealy's tag pipeline: it is a
maintainer-run CalVer script that bumps, tags, pushes, and creates a release,
and public evidence does not show Mealy-style exact-soak promotion or
attestation.

**Lesson for Mealy:** copy the check/backup/migrate/restart/doctor recovery
sequence, not the mutable checkout distribution model.

### OpenCode

Evidence:

- [README install matrix](https://github.com/anomalyco/opencode/blob/62e4641235d7847dadc60da37cca8a023dd54fc1/README.md)
- [first-run guide](https://github.com/anomalyco/opencode/blob/62e4641235d7847dadc60da37cca8a023dd54fc1/packages/web/src/content/docs/index.mdx)
- [providers](https://github.com/anomalyco/opencode/blob/62e4641235d7847dadc60da37cca8a023dd54fc1/packages/web/src/content/docs/providers.mdx)
- [installation/update implementation](https://github.com/anomalyco/opencode/blob/62e4641235d7847dadc60da37cca8a023dd54fc1/packages/opencode/src/installation/index.ts)
- [publish workflow](https://github.com/anomalyco/opencode/blob/62e4641235d7847dadc60da37cca8a023dd54fc1/.github/workflows/publish.yml)

OpenCode distributes a curl installer, npm-compatible packages, Homebrew,
Arch/AUR, Mise, Nix, Scoop, Chocolatey, Docker, standalone assets, and desktop
packages (`.deb`, `.rpm`, AppImage, DMG, and Windows installer). The user runs
`opencode`; `/connect` stores a provider credential and `/models` selects from a
catalog backed by AI SDK and Models.dev. The provider guide covers more than
75 providers, local models, custom base URLs, subscriptions, and curated
starter routes.

The updater detects curl/npm/pnpm/Bun/Homebrew/Scoop/Chocolatey installations
and applies the matching operation. Patch updates can be automatic; larger
updates notify. `opencode upgrade` is explicit, and uninstall supports a
preview plus preservation of config/data.

The documentation is strongly task-oriented and localized. A scheduled
documentation workflow reviews recent user-facing changes, while ordinary CI
builds the documentation. The publish workflow builds CLI and desktop variants
across Linux, macOS, and Windows and signs Windows binaries.

**Lesson for Mealy:** model selection should be a picker backed by observed
provider metadata, and upgrades should respect the original install method.

### Codex

Evidence:

- [repository quickstart](https://github.com/openai/codex/blob/7d748d3bbcbd640988813de962455f27c918abdf/README.md)
- [install/build reference](https://github.com/openai/codex/blob/7d748d3bbcbd640988813de962455f27c918abdf/docs/install.md)
- [current official Codex documentation](https://developers.openai.com/codex)
- [full Rust CI](https://github.com/openai/codex/blob/7d748d3bbcbd640988813de962455f27c918abdf/.github/workflows/rust-ci-full.yml)
- [release workflow](https://github.com/openai/codex/blob/7d748d3bbcbd640988813de962455f27c918abdf/.github/workflows/rust-release.yml)

The current quickstart offers standalone curl/PowerShell installers, npm,
Homebrew, and release binaries. `codex` opens the product and makes
“Sign in with ChatGPT” the recommended subscription path; API-key login is
secondary. The first run supplies a recommended model instead of asking the
user to enter context and pricing data. Current official documentation lists
stable `codex doctor`, `codex update`, and `codex completion` commands,
headless/device authentication, local OSS provider selection, custom providers,
profiles, and shared CLI/IDE configuration.

Public CI covers lint/build matrices and tests on macOS, Linux x86_64/arm64,
and Windows x86_64/arm64 with aggregate gates and representative release-mode
builds. The release pipeline builds and packages targets, handles signing and
distribution metadata, and publishes multiple channels.

Codex's path is exceptionally easy for an OpenAI subscriber but intentionally
not a provider-neutral onboarding model.

**Lesson for Mealy:** a subscription route can be a first-class safe default
without being represented as an API key, and diagnostics/completion belong in
the top-level CLI.

### Vercel AI SDK

Evidence:

- [choosing a provider](https://github.com/vercel/ai/blob/1f6dd3a804743555a1f5e1f066ba3e097e5392c6/content/docs/02-getting-started/00-choosing-a-provider.mdx)
- [coding-agent onboarding](https://github.com/vercel/ai/blob/1f6dd3a804743555a1f5e1f066ba3e097e5392c6/content/docs/02-getting-started/09-coding-agents.mdx)
- [harness overview](https://github.com/vercel/ai/blob/1f6dd3a804743555a1f5e1f066ba3e097e5392c6/content/docs/03-ai-sdk-harnesses/01-overview.mdx)
- [versioning/migrations](https://github.com/vercel/ai/blob/1f6dd3a804743555a1f5e1f066ba3e097e5392c6/content/docs/08-migration-guides/00-versioning.mdx)
- [CI](https://github.com/vercel/ai/blob/1f6dd3a804743555a1f5e1f066ba3e097e5392c6/.github/workflows/ci.yml)
- [release](https://github.com/vercel/ai/blob/1f6dd3a804743555a1f5e1f066ba3e097e5392c6/.github/workflows/release.yml)

AI SDK is installed as a library and cannot be scored as a downloadable
personal assistant. Its applicable strengths are documentation operations:
framework-specific quickstarts, provider-specific examples, a coding-agent
skill, full documentation bundled in the installed npm package, cookbook and
reference layers, explicit versioning policy, major-version migration guides,
and codemods.

CI builds examples and the docs site, validates documentation components,
type-checks, tests supported Node versions, runs RSC E2E, and checks bundle size
and load time. Changesets require public-package changes to carry release notes.
Release automation creates a release PR or publishes and attaches SLSA
provenance.

**Lesson for Mealy:** ship version-matched docs with the product, validate
examples as code, and couple user-visible changes to migration/release notes.

### Eve

Evidence:

- [README quickstart](https://github.com/vercel/eve/blob/876bf3d7afc9029809fbb5ce27a2a2ebbaf6db11/README.md)
- [getting started](https://github.com/vercel/eve/blob/876bf3d7afc9029809fbb5ce27a2a2ebbaf6db11/docs/getting-started.mdx)
- [development TUI](https://github.com/vercel/eve/blob/876bf3d7afc9029809fbb5ce27a2a2ebbaf6db11/docs/guides/dev-tui.md)
- [CLI reference](https://github.com/vercel/eve/blob/876bf3d7afc9029809fbb5ce27a2a2ebbaf6db11/docs/reference/cli.md)
- [CI](https://github.com/vercel/eve/blob/876bf3d7afc9029809fbb5ce27a2a2ebbaf6db11/.github/workflows/ci.yml)
- [local E2E](https://github.com/vercel/eve/blob/876bf3d7afc9029809fbb5ce27a2a2ebbaf6db11/.github/workflows/e2e-local.yml)

`npx eve@latest init my-agent` creates a project, installs dependencies,
initializes Git, and starts the interactive TUI. A missing credential is not
just an error: `/model` guides the user through a key or Vercel project link.
The TUI keeps `/model`, `/channels`, `/connect`, and `/deploy` close to the
conversation. Full docs are bundled in the npm package for version-matched
offline access.

The scaffold is tested from a packed release tarball and covers fresh projects,
existing projects, package-manager behavior, Git initialization, and
coding-agent launches. CI separates unit, integration, scenario, TUI, Windows,
local E2E, Vercel E2E, and container paths. Release uses queued Changesets
publication to avoid a partially published package set.

Eve is a beta TypeScript framework, requires Node 24, and is oriented toward
building/deploying agents rather than installing a general personal assistant.

**Lesson for Mealy:** test the released onboarding artifact from an empty home,
including the exact handoff into the first conversation.

### Pi

Evidence:

- [coding-agent README](https://github.com/earendil-works/pi/blob/65ff8e7f6db447dcddb1a9c8fd05f081c5cda76a/packages/coding-agent/README.md)
- [provider setup](https://github.com/earendil-works/pi/blob/65ff8e7f6db447dcddb1a9c8fd05f081c5cda76a/packages/coding-agent/docs/providers.md)
- [custom models/endpoints](https://github.com/earendil-works/pi/blob/65ff8e7f6db447dcddb1a9c8fd05f081c5cda76a/packages/coding-agent/docs/models.md)
- [packages and updates](https://github.com/earendil-works/pi/blob/65ff8e7f6db447dcddb1a9c8fd05f081c5cda76a/packages/coding-agent/docs/packages.md)
- [binary release workflow](https://github.com/earendil-works/pi/blob/65ff8e7f6db447dcddb1a9c8fd05f081c5cda76a/.github/workflows/build-binaries.yml)

Pi offers npm and curl installation, then starts with `pi`. `/login` supports
Claude, ChatGPT/Codex, and Copilot subscriptions as well as a broad API-key
catalog; `/model` uses automatically refreshed tool-capable model catalogs.
OpenRouter, local llama.cpp, Ollama/LM Studio/vLLM-compatible endpoints, custom
headers, environment/command credential resolution, and dynamically registered
providers are documented.

The daily TUI has model/cost/context status, session resume/branch/fork/import/
export, automatic compaction, project trust, skills, extensions, and package
management. `pi update` can update the CLI, extensions, or model catalogs
separately.

Pi's release workflow has valuable controls: build from a versioned source
archive, create all cross-platform binaries, generate checksums, validate the
payload, stage a draft GitHub release, run build/check/test before trusted npm
publication, publish the GitHub release last, and delete the draft after
failure. Scheduled npm vulnerability and registry-signature audits supplement
ordinary CI.

Pi explicitly states that it has no built-in filesystem/process/network
permission sandbox and recommends external isolation. Mealy must not copy that
security posture.

**Lesson for Mealy:** copy the unified login/model picker and separated
self/package/catalog updates while retaining Mealy's enforced authority
boundaries.

### Claude Code

Evidence:

- [official repository quickstart](https://github.com/anthropics/claude-code/blob/2982f951552e94f38cd972764ae94c1d90c41da3/README.md)
- [official setup documentation](https://code.claude.com/docs/en/setup)
- [official CLI reference](https://code.claude.com/docs/en/cli-reference)
- [public changelog](https://github.com/anthropics/claude-code/blob/2982f951552e94f38cd972764ae94c1d90c41da3/CHANGELOG.md)

Official setup offers native curl/PowerShell installers, Homebrew, WinGet, and
the now-deprecated npm path. The user starts `claude` and signs in with a Claude
subscription, Console account, or supported enterprise platform. Native
installs check and apply updates in the background; Homebrew and WinGet retain
package-manager updates. Stable/latest channels, manual `claude update`, and
`claude doctor` are documented.

The official docs cover quickstart, settings, memory, hooks, MCP, plugins,
troubleshooting, IDEs, CI, and enterprise deployment. The public repository
contains the changelog, issue tracker, release records, and plugins, but its
visible workflows are primarily issue maintenance and triage. Product build,
test, signing, and release controls are not publicly auditable from this
repository.

**Lesson for Mealy:** make first-run subscription login and background update
status simple, while preserving public build provenance that Claude Code does
not expose.

## Cross-system patterns that are supported by evidence

### 1. First-run success is one product transaction

The strongest flows do not stop after copying a binary:

- OpenClaw installs, onboards, configures its daemon, and opens a usable
  surface.
- Hermes installs dependencies and provider configuration, then `hermes`
  chats.
- OpenCode starts the TUI and keeps `/connect` and `/models` inside it.
- Codex and Claude Code authenticate on launch.
- Eve scaffolds, installs, initializes Git, and starts the TUI.
- Pi starts with `pi`, then keeps login and model selection in the TUI.

### 2. Users select capabilities, not token-accounting internals

Successful onboarding asks for a provider/account and model, normally through a
catalog. It does not ask a new user to research:

- exact context windows;
- output-token ceilings; or
- per-million input/output prices.

Advanced overrides remain possible, but defaults come from maintained metadata.

### 3. Subscription login is distinct from API-key login

Codex, Claude Code, Pi, Hermes, and OpenCode present subscription/OAuth paths as
named account types. They do not imply that a consumer subscription is an API
key. Mealy's underlying bridge follows this boundary correctly, but its guided
setup hides the routes behind advanced configuration commands.

### 4. Update behavior follows install provenance

OpenCode detects curl and package-manager installs. Hermes detects git,
Docker, and Nix layouts. Claude Code separates native auto-update from
Homebrew/WinGet. Pi detects whether self-update is supported and otherwise
prints the correct instruction.

### 5. Repair, migration, and rollback are user-facing features

OpenClaw and Hermes are the clearest examples. A production update is not only
“download newer bytes”; it includes backup, migration, restart, health,
diagnostics, recovery, and a comprehensible log.

### 6. Documentation is layered and executable

The common information architecture is:

1. a very short install/first-run path;
2. provider and platform guides;
3. task-oriented daily-use guides;
4. troubleshooting and doctor;
5. an exhaustive CLI/config reference; and
6. maintainer/release material kept outside the new-user path.

Eve and AI SDK bundle docs with the installed package. AI SDK, Eve, Hermes, and
OpenClaw build or validate docs in CI. Eve and AI SDK also exercise examples or
scaffolds rather than treating snippets as inert prose.

### 7. Release validation includes the user journey

The highest-value public checks are not only language-level tests:

- install scripts on clean hosts;
- packed/npm/native artifact installation;
- first-run/scaffold behavior;
- provider/login/model setup with safe fixtures;
- service start and health;
- upgrade/uninstall behavior; and
- exact release payload validation.

Mealy already has strong installed-package, service, provider, distro, soak,
SBOM, and attestation gates. The missing release test is a single clean-home
onboarding-to-chat journey.

## Mealy baseline at `8867c46774c693a335853625dd967fd3520976ff`

### Already stronger than many comparators

- durable sessions, effects, approvals, recovery, schedules, and channels;
- brokered secret containment;
- local-only authenticated control plane;
- sandbox and digest-pinned executable boundaries;
- `doctor`, status, metrics, backup, isolated restore verification, and
  rollback primitives;
- deterministic release archives plus Debian, Ubuntu, Fedora/RPM, and Arch
  package validation on x86_64 and qualified arm64 lanes;
- exact 24-hour soaked daemon promotion;
- protected-main CI and exact free-OpenRouter acceptance requirements;
- SBOM, third-party notices, checksums, GitHub artifact attestations, and public
  install verification; and
- documentation/API/CLI consistency validation in CI.

### Current first-run path

The verified installer:

1. requires GitHub CLI for attestation verification;
2. downloads and verifies release metadata/assets;
3. installs `mealyd` and `mealyctl` rootlessly;
4. prints setup and service-install commands; and
5. stops.

The user then runs `mealyctl setup`, chooses a provider and exact model, supplies
context/output limits and remote prices, approves activation, installs a
service definition, executes a separately printed activation command, waits
for the daemon, runs `doctor`, and starts `chat`.

Mealy already has model discovery commands for OpenAI, Anthropic, OpenRouter,
and local endpoints. It also has separate OpenAI/ChatGPT and Claude subscription
configuration, a generic custom base URL mechanism, and service installation.
The weakness is that the guided path does not compose them.

## Gap matrix

Legend: **Yes** = integrated and documented; **Partial** = capability exists but
the ordinary user journey is incomplete; **No** = no comparable product path;
**N/A** = framework is not an equivalent installed assistant.

| Product operation | Mealy | OpenClaw | Hermes | OpenCode | Codex | Eve | Pi | Claude Code |
|---|---|---|---|---|---|---|---|---|
| One short install command | Partial | Yes | Yes | Yes | Yes | N/A | Yes | Yes |
| Native/package-manager choices | Partial | Partial | Partial | Yes | Yes | N/A | Yes | Yes |
| Installer reaches first-run setup | No | Yes | Yes | Yes | Yes | N/A | Yes | Yes |
| In-product provider/model picker | Partial | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Subscription login in normal setup | Partial | Yes | Yes | Partial | Yes | N/A | Yes | Yes |
| Custom/local endpoint in normal setup | Partial | Yes | Yes | Yes | Partial | Partial | Partial | No |
| Curated or metadata-derived defaults | No | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Service/background activation composed | Partial | Yes | Yes | N/A | N/A | N/A | N/A | N/A |
| Health/doctor command | Yes | Yes | Yes | Partial | Yes | N/A | Partial | Yes |
| Install-aware update command | No | Yes | Yes | Yes | Yes | N/A | Yes | Yes |
| Pre-update backup/rollback path | Partial | Yes | Yes | Partial | Partial | N/A | Partial | Partial |
| Config migration/repair UX | Partial | Yes | Yes | Partial | Partial | Yes | Partial | Yes |
| Uninstall command | No | Yes | Yes | Yes | Partial | N/A | Documented | Documented |
| Shell completion | No | Yes | Yes | Partial | Yes | N/A | Partial | Yes |
| Short first-five-minute document | No | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Version-matched bundled docs | Yes | Partial | Partial | Partial | Partial | Yes | Yes | Partial |
| Clean-artifact onboarding test | Partial | Yes | Partial | Partial | Yes | Yes | Yes | Not publicly evidenced |
| Public cross-platform/distro CI | Linux-focused | Yes | Yes | Yes | Yes | Partial | Partial | Not publicly evidenced |
| Public staged/attested release | Yes, pending first publication | Partial | Partial | Partial | Partial | SLSA npm | Checksums/staged | Not publicly evidenced |

## Prioritized Mealy remediation

### P0 — preserve the v0.1.1 release boundary

- Let the exact v0.1.1 daemon finish its existing 24-hour soak.
- Do not change or rebuild its candidate binary.
- Complete final package validation, free-model OpenRouter acceptance,
  protected-main CI selection, and attested publication from that exact
  candidate.
- Develop onboarding improvements on a separate branch for the next release.

### P1 — one guided onboarding transaction

Add `mealyctl onboard` as a composition layer over existing governed
operations:

1. detect an existing home and choose resume/reconfigure/diagnose safely;
2. offer named routes:
   - OpenRouter — free tool-capable model;
   - custom OpenAI-compatible endpoint;
   - local credentialless endpoint;
   - ChatGPT subscription through the official Codex client;
   - Claude subscription through the official Claude client;
   - advanced OpenAI or Anthropic API setup;
3. fetch model metadata and present eligible models;
4. derive limits and posted prices where the provider supplies them;
5. show the exact non-secret plan and require explicit approval;
6. configure and live-probe the selected route;
7. install the user service, start it, and wait for bounded health;
8. run `doctor`; and
9. open chat or print one exact next command for non-interactive use.

Required failure behavior:

- never print or persist plaintext credentials outside the broker;
- never call paid OpenRouter models in the “free” flow;
- never silently replace an existing home;
- stop and preserve diagnostics if service health fails;
- leave a successfully configured but unstarted home recoverable;
- make every mutation idempotent or explicitly report the completed boundary.

### P1 — first-five-minute documentation

Create a short `docs/GETTING_STARTED.md` that contains only:

1. supported Linux prerequisites;
2. verified release install;
3. `mealyctl onboard`;
4. the five authentication route choices;
5. first chat;
6. `doctor`; and
7. links to detailed Linux, provider, operation, and release references.

Keep `QUICKSTART.md` as the comprehensive operator guide. The README should lead
with the short path and move implementation inventory behind reference links.

### P1 — acceptance test for the real journey

From a clean home and installed release payload, test:

- each deterministic/fixture onboarding branch;
- OpenRouter free catalog filtering and selection;
- a custom authenticated OpenAI-compatible endpoint;
- subscription-client signed-out and signed-in detection without exposing
  credentials;
- service installation/start/health/doctor;
- first chat and durable resume; and
- rerunning onboarding without corrupting the existing home.

Live secrets remain only in protected provider acceptance. Ordinary CI uses
fixture endpoints and fake service-manager isolation.

### P2 — lifecycle commands

- `mealyctl update --check` and `mealyctl update`, aware of archive/deb/rpm/Arch
  installation provenance;
- pre-update backup, schema compatibility check, staged replacement, service
  restart, health verification, and automatic package rollback;
- `mealyctl repair` as a safe composition of diagnostics and explicitly scoped
  fixes;
- plan-first archive uninstall that always preserves durable state and removes
  only an independently verified generated service definition; and
- generated Bash, Zsh, and Fish completion.

### P2 — broader Linux distribution ergonomics

The release already produces and tests `.deb`, `.rpm`, and Arch packages.
Ease-of-use still trails competitors until users can obtain updates through
normal repositories. Add signed:

- APT repository metadata for Debian/Ubuntu families;
- RPM repository metadata for Fedora/RHEL-like families; and
- an Arch package repository or clearly maintained AUR path.

Derivatives remain compatibility-expected, not qualified, unless their libc,
systemd user-manager, Bubblewrap/AppArmor/SELinux, or package-format behavior
diverges from the documented family contract.

### P3 — daily-use product polish

- model switching and provider health inside chat;
- a clearer model/cost/context status line;
- friendlier first-run and recovery errors with exact remediation commands;
- session browse/resume/fork/export in one interactive picker;
- setup for Telegram/Discord and optional capabilities from the same guided
  surface;
- a searchable documentation site generated from the checked Markdown; and
- screenshots or terminal recordings validated against the release.

Post-benchmark implementation status: the first daily-use slice now places authenticated provider
health in chat and adds startup plus refreshable `/status` views for model, locality, context/output
limits, provider overhead, configured prices, queue state, and per-route pressure. Terminal turns
also show exact durable tokens, provider-neutral cost microunits, model/tool calls, and retries.
The next slice adds the competitor-familiar `chat --continue`/`-c` path: it selects the newest
exact-binding session, performs the existing bounded durable-work rediscovery, and never creates a
duplicate when no history exists. A subsequent slice adds `chat --pick`: a terminal-only,
20-session exact-binding chooser that shows status, relative recency, and active/queued work,
resumes only the selected durable session, and creates nothing while browsing. Branching and
transcript export remain later polish.
Provider switching deliberately remains a stopped-daemon transaction until a guided flow can
preserve the existing review, restart, health, and rollback boundary.

## Definition of competitor-grade onboarding

The onboarding goal is complete only when an ordinary supported-Linux user can:

1. obtain an attested Mealy package without a Rust toolchain;
2. run one guided command;
3. choose a free, subscription, local, custom, or advanced API route without
   researching token accounting;
4. see the route pass a live bounded probe;
5. have the owner service installed and running;
6. reach the first useful chat;
7. restart the machine and resume;
8. diagnose a failure with one command;
9. update and roll back without losing state; and
10. find the same workflow in a short, version-matched document.

Security and durability are not traded for convenience. The single flow must
remain an orchestrator over Mealy's existing approval, credential, package,
service, and recovery boundaries.
