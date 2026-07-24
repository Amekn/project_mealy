# Get started on Linux

This is the shortest path from a verified Mealy installation to a useful chat on a supported
Linux host. It applies to Ubuntu, Debian, Fedora, and Arch Linux; read the
[Linux support contract](LINUX_SUPPORT.md) for exact qualified versions and derivative limits.

No production release exists merely because source code is present. Before installing, confirm
that the selected GitHub release is published, attested, and has green linked acceptance jobs as
described in the [release guide](RELEASE.md).

## 1. Install a verified release

The shortest distribution-native route is the versioned
[signed repository landing page](https://amekn.github.io/mealy/) and the corresponding APT, DNF,
or Pacman setup in [LINUX_REPOSITORIES.md](LINUX_REPOSITORIES.md). Those package managers install
Mealy's Bubblewrap, CA-certificate, libc, and runtime dependencies; the setup step itself uses
`curl` to download a small configuration file for inspection. The landing page is part of the
repository's signed complete inventory and gives inspect-before-privilege commands for all three
families; use it only after the selected release's publication and public-install jobs are green.

For the attestation-verifying rootless release bootstrap, first install Bubblewrap, GitHub CLI,
`curl`, `jq`, and the ordinary host packages listed in the
[quickstart prerequisites](QUICKSTART.md#prerequisites). The
[fast install instructions](QUICKSTART.md#fast-verified-linux-install) remain available when the
repository has not yet been deployed or root access is undesirable. Neither route requires a Rust
toolchain. The verified bootstrap continues directly into this guide's onboarding flow on an
interactive fresh install; use its `--no-onboard` option when installation must remain passive.

Make sure `$HOME/.local/bin` is on `PATH`, then check the installed client:

```sh
mealyctl --version
```

Mealy uses the private durable `$HOME/.mealy` directory by default. That location does not change
when you run commands from a different working directory. Set `MEALY_HOME` or pass `--home` only
when you intentionally need another owner-private location.

## 2. Choose how Mealy reaches a model

Bare `mealyctl` enters onboarding when the private home is not configured. The guided chooser
offers these routes:

| Choice | What must already exist |
| --- | --- |
| OpenRouter free | An OpenRouter key. Set `OPENROUTER_API_KEY` for automation, or enter it at the hidden prompt in an interactive terminal. Mealy admits only a live catalog model whose exact ID ends in `:free`, supports tools/text, has complete limits, and advertises zero token and auxiliary prices. |
| Custom endpoint | An OpenAI Responses-compatible HTTPS `/v1` endpoint and its key. Set a named environment variable for automation, or enter the key at the hidden interactive prompt. |
| Local endpoint | A credentialless Responses-compatible server on a literal loopback IP. |
| ChatGPT subscription | The official `codex` client installed and already signed in with ChatGPT. |
| Claude subscription | The official `claude` client installed and already signed in with a Claude subscription. |
| OpenAI API | `OPENAI_API_KEY`. |
| Anthropic API | `ANTHROPIC_API_KEY`. |

Subscription routes use the existing official client session. Mealy does not extract OAuth tokens,
inherit API-key variables into that client, or treat a ChatGPT/Claude subscription as an API key.

## 3. Run or continue onboarding

If the verified bootstrap already opened onboarding, choose the matching route at its prompt.
After a native-package or passive bootstrap install, the shortest terminal command is:

```sh
mealyctl
```

Scripts should use one of the explicit `mealyctl onboard --route ...` forms below. A bare command
requires interactive stdin, stdout, and stderr, so it never guesses or mutates when used in
automation.

For the recommended no-paid-credit route:

```sh
mealyctl onboard --route openrouter-free
```

If `OPENROUTER_API_KEY` is absent, interactive onboarding asks for it with terminal echo disabled,
then restores normal echo before the next prompt. Mealy fetches the account-visible catalog, shows
only strictly eligible free models, derives their advertised limits and zero price, live-probes the
selected model, brokers the key, installs and starts the systemd user service, waits for health,
and requires `doctor` to pass. It prints the complete non-secret plan before asking you to type
`APPROVE`.

For an authenticated custom endpoint:

```sh
mealyctl onboard \
  --route custom \
  --base-url 'https://your-endpoint.example/v1'
```

The default automation variable is `CUSTOM_API_KEY`. Use `--credential-env LOCAL_API_KEY` when
that is the variable name chosen for a private remote endpoint. If the selected variable is absent,
interactive onboarding prompts securely instead. Never put the credential value itself on the
command line. Non-interactive onboarding never attempts a prompt: set the named variable and pass
the other complete flags, including `--approve`.

For a credentialless loopback server:

```sh
mealyctl onboard \
  --route local \
  --base-url 'http://127.0.0.1:11434/v1'
```

For a subscription, first complete sign-in in the official client, then choose
`chatgpt-subscription` or `claude-subscription`:

```sh
mealyctl onboard --route chatgpt-subscription
```

Onboarding refuses to replace an existing `config.json`. Diagnose an existing running home with
`doctor`; only use `--reconfigure` after stopping the daemon and intentionally reviewing the new
provider plan. `--configure-only` is available for a foreground or test installation and
deliberately skips service installation, startup, health, and doctor verification.
`--skip-connectivity-test` is accepted only together with `--configure-only`, so an unprobed
provider cannot be presented as fully onboarded.

## 4. Chat and verify

On a real terminal, successful full onboarding opens the first durable chat automatically after
service health and `doctor` pass. Type a prompt at `you>`. Use `--no-chat` when you want onboarding
to stop and print the exact next command, or `--chat` to force the chat handoff for a deliberately
scripted terminal session.

After configuration, bare `mealyctl` opens a separate new durable conversation:

```sh
mealyctl
```

To return later, continue the most recently updated conversation for this exact local
owner/channel binding:

```sh
mealyctl chat --continue
```

The explicit equivalent, useful in scripts, is:

```sh
mealyctl chat
```

`--continue` (or `-c`) reopens the latest session and rediscovers its active and queued durable
work. It never silently creates a new session; when no prior conversation exists, the client tells
you to start one with plain `chat`.

To choose an older conversation without copying a session ID:

```sh
mealyctl chat --pick
```

The terminal-only picker shows at most 20 owner/channel-bound conversations, newest first, with
their status, relative recency, and queued/active work. Selecting one resumes that exact durable
session and creates nothing new.

`/status` shows the live provider/model, health, locality, context/output limits, exact configured
prices, and current request pressure. Every terminal turn prints its recorded input/output tokens,
provider-neutral cost microunits, model/tool calls, and retries. `/help` lists session controls,
approvals, memory, attachments, and governed action modes. The owner service survives logout/reboot
when the host's systemd user manager and lingering policy provide that behavior.

Recheck the installation at any time:

```sh
mealyctl install-status
mealyctl doctor
mealyctl status
```

Stop before changing provider or other stopped-home configuration:

```sh
mealyctl drain
```

Check for an attested stable update without changing anything:

```sh
mealyctl update
```

The plan identifies an owner-local archive or the native Debian, RPM, or Arch package manager. An
explicitly approved same-schema archive update takes its own backup, drains and restarts the
verified owner service through a disconnect-resistant helper, checks health and `doctor`, and
automatically restores the prior slot if qualification fails. Use `update-status TRANSACTION_UUID`
after reconnecting. Schema changes use the staged migration procedure, and native packages use the
exact command in `nativeUpdateCommand`. `repair`, `rollback`, and `uninstall` follow the same
plan-first/approve-second pattern and never delete the Mealy home.

Optional shell completion is generated locally:

```sh
mealyctl completion bash >"$HOME/.local/share/bash-completion/completions/mealyctl"
```

Continue with the comprehensive [quickstart](QUICKSTART.md) for workspace tools, web/browser,
skills, MCP, memory, channels, schedules, backup, and recovery. Use the
[operations guide](OPERATIONS.md) for incidents and the [CLI reference](CLI.md) for every command.
