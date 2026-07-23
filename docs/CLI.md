# Command-line reference

`mealyctl` is the supported owner-facing client for Mealy's local authenticated API and
stopped-home configuration boundaries. The global form is:

```sh
mealyctl --home "$HOME/.mealy" COMMAND [OPTIONS]
```

`--home` may also come from `MEALY_HOME`. Keep it on owner-private durable storage. Do not place
the local bearer token or a provider credential directly on a command line; provider setup imports
the named environment variable into Mealy's private broker and stores only its opaque reference.

Run `mealyctl --help` for the current public surface and `mealyctl COMMAND --help` for the exact
arguments of one command. Protected CI compares that real help output with the table below, so a
public command cannot be added or removed without updating this reference.

## Public commands

| Command | Purpose |
| --- | --- |
| `onboard` | Configure one provider route, install/start the Linux owner service, and verify health and doctor. |
| `setup` | Initialize a clean stopped home and activate one bounded provider configuration. |
| `chat` | Start or resume the interactive durable conversation client. |
| `session` | Create, submit to, inspect, search, or watch durable sessions. |
| `task` | Inspect, cancel, pause, resume, or replay durable agent tasks. |
| `delegation` | Inspect durable parent-to-child agent delegations. |
| `approval` | Inspect and resolve authenticated approval subjects. |
| `effect` | Inspect governed effects, dispatch attempts, and reconciliation evidence. |
| `memory` | Manage governed long-term memory, retrieval, export, and index rebuilding. |
| `compaction` | Create or inspect cited derived session compactions. |
| `extension` | Install, grant, invoke, upgrade, disable, or revoke isolated extensions. |
| `skill` | Inspect and manage stopped-home data-only skill bundles. |
| `channel` | Configure and inspect webhook, Telegram, and Discord channel bindings. |
| `schedule` | Create, inspect, pause, resume, cancel, or audit recurring schedules. |
| `health` | Check daemon liveness. |
| `status` | Inspect queues, leases, providers, approvals, effects, channels, and storage. |
| `metrics` | Emit stable machine-readable operational gauges. |
| `usage` | Emit exact settled terminal-run usage for a bounded trailing day range. |
| `doctor` | Diagnose control-plane, permission, and sandbox conformance. |
| `install-status` | Inspect install provenance, complete release integrity, rollback availability, and update ownership. |
| `update` | Verify a stable release target and optionally apply a same-schema archive update. |
| `repair` | Verify and optionally restore owner-local installation-management evidence. |
| `rollback` | Verify and optionally exchange same-schema owner-local release slots. |
| `uninstall` | Verify and optionally remove program files while preserving durable state. |
| `completion` | Generate native Bash, Zsh, or Fish completion. |
| `dashboard` | Serve a temporary least-authority loopback dashboard. |
| `drain` | Close admission and begin bounded graceful daemon shutdown. |
| `backup` | Create an immutable complete online backup. |
| `restore-verify` | Restore into an isolated fresh home and verify without replacement. |
| `restore-activate` | Activate one exact verified encrypted backup while stopped. |
| `garbage-collect` | Erase only eligible unreferenced artifact files. |
| `export` | Publish an immutable owner-scoped evidence bundle. |
| `service` | Render and install an owner-level systemd user unit on supported Linux hosts. |
| `config` | Inspect or change governed stopped-home configuration. |

Most non-interactive commands emit one bounded JSON value on standard output and diagnostics on
standard error. Scripts should validate `apiVersion`, named fields, and the process exit status;
they must not infer success from human-readable text. `chat`, `dashboard`, setup approval prompts,
and selected pairing flows are intentionally interactive unless their documented explicit flags
choose a bounded non-interactive path.

## Common workflows

- Follow [getting started](GETTING_STARTED.md) for verified installation, one-command onboarding,
  and the first chat.
- Follow the [quickstart](QUICKSTART.md) for detailed provider activation, first
  conversation, skills, tools, channels, schedules, and delegation.
- Use the [operations guide](OPERATIONS.md) for health, metrics, drain, backup/restore, retention,
  service management, upgrades, and incidents.
- Use the [local API reference](API.md) when building a direct client rather than invoking
  `mealyctl`.
- Use the [release guide](RELEASE.md) for attestation verification, installation, rollback, and
  uninstall of published packages.

Commands that mutate stopped-home configuration require the daemon lock to be free and normally
require exact explicit approval. Commands against a running daemon authenticate through the
owner-only `connection.json`. Safe mode and drain intentionally reject ordinary mutations; consult
the command's JSON error and retryability contract instead of bypassing those states.

## Installation status and completion

`mealyctl install-status` is offline and emits `mealy.install-status.v1`. A published installation
is reported as healthy only after every checksum-declared file—including both binaries, the stable
manager inputs, the release bootstrap, documentation, SBOM, and license notices—has been read as a
bounded no-follow regular file and matched its release digest. It distinguishes owner-local archive
slots from Debian, RPM, and Arch package ownership. Source builds and unknown layouts never acquire
a mutating update backend.

`mealyctl --home "$HOME/.mealy" update` performs a no-mutation check by default. The bundled,
release-digest-bound bootstrap downloads the selected stable release, verifies its exact hosted
GitHub Actions provenance from the tag, verifies the complete outer checksum inventory, and reads
the target manifest from the attested archive. The resulting `mealy.update-plan.v1` identifies the
current and target versions and state schemas.

An owner-local archive update may be applied with `--approve` only when the target is strictly
newer and uses the exact active state schema. Drain and stop `mealy.service` first; the stable
manager independently refuses a busy home, re-verifies the download, swaps atomic release slots,
and preserves the previous matching slot for rollback. A target with a different state schema is
deliberately refused by this convenience path and must use the staged migration procedure in the
[release guide](RELEASE.md). Debian, RPM, and Arch installations always retain native package
ownership; the plan reports the exact `apt`, `dnf`, or `pacman` handoff and never writes `/usr`.

`repair`, `rollback`, and `uninstall` also plan without mutation unless `--approve` is present.
Repair can reconstruct a missing or modified stable archive manager only from the checksum-verified
active metadata copy; it cannot repair around a changed binary or manifest. Rollback delegates only
when both complete archive slots verify, and the stable manager independently refuses a backward
state-schema transition. Uninstall removes managed program files only and always preserves the
complete Mealy home. Drain and stop the owner service before rollback or uninstall. Native packages
return the exact `apt`, `dnf`, or `pacman` repair/uninstall command so `/usr` remains under the
distribution package database.

Generate completion without starting the daemon or reading private state:

```sh
# Bash
mealyctl completion bash >"$HOME/.local/share/bash-completion/completions/mealyctl"

# Zsh
mealyctl completion zsh >"$HOME/.local/share/zsh/site-functions/_mealyctl"

# Fish
mealyctl completion fish >"$HOME/.config/fish/completions/mealyctl.fish"
```

## Onboarding routes

`mealyctl --home "$HOME/.mealy" onboard` is the ordinary clean-install path. It prompts for one of
seven explicit routes: `openrouter-free`, `custom`, `local`, `chatgpt-subscription`,
`claude-subscription`, `openai-api`, or `anthropic-api`.

The OpenRouter route fetches the live account catalog and admits only tool-capable text models
whose exact ID ends in `:free`, whose context/output limits are complete, and whose posted
input/output plus auxiliary prices are exactly zero. Custom and official API routes import a
credential from a named environment variable into the private broker. The local route requires a
literal-loopback endpoint and no credential. Subscription routes pin and live-probe the installed
official Codex or Claude executable without extracting its subscription credential.

Before mutation, onboarding prints a non-secret provider digest and its service action, then
requires the exact word `APPROVE` unless `--approve` was given. A pre-existing configuration is
rejected unless `--reconfigure` explicitly acknowledges replacement while the daemon is stopped.
The normal Linux path installs and starts `mealy.service`, waits up to 30 seconds, and requires
liveness, control-plane readiness, and an available sandbox. `--configure-only` deliberately stops
after provider activation and reports the exact service-install command as the next step.
`--skip-connectivity-test` requires that configure-only mode, preventing a staged provider from
being reported as a verified running onboarding result.
