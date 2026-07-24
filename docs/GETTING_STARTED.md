# Get started on Linux

This is the shortest supported path from installation to a useful Mealy chat on Ubuntu, Debian,
Fedora, or Arch Linux. No source checkout or Rust toolchain is required.

## 1. Install

Use the versioned [signed repository landing page](https://amekn.github.io/mealy/) for the shortest
APT, DNF, or Pacman path. Use that page only after the selected release shows green publication
and public-install jobs. The [package-manager guide](LINUX_REPOSITORIES.md) contains the same
inspect-before-privilege commands and independent trust verification.

For a rootless install, follow the
[attested release bootstrap](QUICKSTART.md#fast-verified-linux-install). It selects the host
architecture, verifies the release workflow and checksums, installs beneath `$HOME/.local`, and
continues into onboarding on a fresh interactive home. It needs no root access or GitHub account.

Confirm the installed command is on `PATH`:

```sh
mealyctl --version
```

Mealy keeps its private durable state in `$HOME/.mealy` by default. See the
[Linux support contract](LINUX_SUPPORT.md) for qualified versions, required host facilities, and
derivative limits.

## 2. Start

Run one command in a terminal:

```sh
mealyctl
```

On a clean home, this opens guided onboarding. After configuration, the same command opens a new
durable chat. Scripts must use explicit subcommands so automation never guesses or prompts.

Choose one route:

| Route | What you need |
| --- | --- |
| OpenRouter free | An OpenRouter key. Mealy admits only account-visible tool/text models whose exact ID ends in `:free` and whose complete advertised prices are zero. |
| Custom endpoint | An HTTPS OpenAI Responses-compatible `/v1` endpoint and its key. |
| Local endpoint | A credentialless Responses-compatible server on a literal loopback IP. |
| ChatGPT subscription | The official `codex` client and its existing ChatGPT session, or consent to its official browser/device sign-in. |
| OpenAI or Anthropic API | The corresponding API key for an advanced direct route. |

Remote keys can come from the named environment variable or a bounded hidden terminal prompt.
Mealy never puts a credential in command history or configuration. ChatGPT credentials remain
owned by the official Codex client. Claude Free, Pro, and Max subscription routing is not
supported because Anthropic prohibits third-party use; the Anthropic API remains supported.

The guided flow discovers eligible models, derives limits and prices when available, live-probes
the selected route, displays a non-secret plan, and asks you to type `APPROVE`. It then installs
and starts the owner service, waits for health, requires `doctor` to pass, and opens chat.

## 3. Explicit route commands

Use these forms when you already know the route:

```sh
# Strictly zero-price OpenRouter catalog
mealyctl onboard --route openrouter-free

# Authenticated custom Responses endpoint; hidden prompt if CUSTOM_API_KEY is absent
mealyctl onboard --route custom --base-url 'https://your-endpoint.example/v1'

# Credentialless loopback server
mealyctl onboard --route local --base-url 'http://127.0.0.1:11434/v1'

# Existing or officially authenticated ChatGPT subscription
mealyctl onboard --route chatgpt-subscription
```

For a private remote endpoint whose key is already named `LOCAL_API_KEY`, add
`--credential-env LOCAL_API_KEY`; never pass the key value itself. On a headless ChatGPT host, add
`--chatgpt-login device-code`. OpenAI and Anthropic API routes are available in the chooser and
documented in the [provider quickstart](QUICKSTART.md#credentialed-openai-or-anthropic).

Onboarding refuses to overwrite an existing configuration. Use `doctor` for an existing home;
reconfigure only after stopping the service and deliberately reviewing the replacement plan.

## 4. Chat, return, and diagnose

Type a prompt at `you>`. `/status` shows the selected provider/model, health, limits, configured
prices, and request pressure; `/help` lists chat controls, approvals, memory, attachments, and
governed actions.

Return to the newest durable conversation:

```sh
mealyctl chat --continue
```

Or choose from the 20 most recent owner-bound conversations:

```sh
mealyctl chat --pick
```

Check the installation and service:

```sh
mealyctl install-status
mealyctl doctor
mealyctl status
```

Check for an attested stable update without changing anything:

```sh
mealyctl update
```

Update, repair, rollback, service removal, and uninstall are plan-first and preserve the Mealy
home. Owner-local archive updates back up, restart, qualify, and automatically restore the prior
same-schema slot on failure; native packages hand off to APT, DNF, or Pacman.

## Learn more

- [Comprehensive quickstart](QUICKSTART.md): providers, tools, browser, MCP, memory, channels,
  schedules, backup, and recovery
- [CLI reference](CLI.md): every public command and option
- [Operations guide](OPERATIONS.md): diagnostics, backup, recovery, and incidents
- [Release guide](RELEASE.md): attestation, packages, updates, rollback, and publication evidence
- [Security model](THREAT_MODEL.md): trust boundaries and supported limitations
