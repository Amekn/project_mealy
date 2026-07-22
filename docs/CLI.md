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
| `dashboard` | Serve a temporary least-authority loopback dashboard. |
| `drain` | Close admission and begin bounded graceful daemon shutdown. |
| `backup` | Create an immutable complete online backup. |
| `restore-verify` | Restore into an isolated fresh home and verify without replacement. |
| `restore-activate` | Activate one exact verified encrypted backup while stopped. |
| `garbage-collect` | Erase only eligible unreferenced artifact files. |
| `export` | Publish an immutable owner-scoped evidence bundle. |
| `service` | Render and install an owner-level systemd unit or macOS LaunchAgent. |
| `config` | Inspect or change governed stopped-home configuration. |

Most non-interactive commands emit one bounded JSON value on standard output and diagnostics on
standard error. Scripts should validate `apiVersion`, named fields, and the process exit status;
they must not infer success from human-readable text. `chat`, `dashboard`, setup approval prompts,
and selected pairing flows are intentionally interactive unless their documented explicit flags
choose a bounded non-interactive path.

## Common workflows

- Follow the [quickstart](QUICKSTART.md) for verified installation, provider activation, first
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
