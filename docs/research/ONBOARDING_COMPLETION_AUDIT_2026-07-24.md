# Competitor-grade onboarding completion audit

Observed: 2026-07-24 (Pacific/Auckland)

Standard: the ten-item definition in
[PRODUCT_OPERATIONS_BENCHMARK_2026-07-24.md](PRODUCT_OPERATIONS_BENCHMARK_2026-07-24.md#definition-of-competitor-grade-onboarding)

This audit separates implemented source behavior from a publicly usable production release. A
green pull-request check proves the exact source revision it tested; it does not prove that the
revision is merged, tagged, published, or installed by an ordinary user. “Source-ready” below
therefore remains distinct from “publicly complete.”

At the 2026-07-24T15:03:19+12:00 delivery recheck, v0.1.0 was a public immutable
stable release with green native package, attestation, and public archive
acceptance. It predates this onboarding stack and the signed Linux repository
workflow. The configured Pages URL still returned HTTP 404, so documentation
must not describe APT, DNF, or Pacman publication as an already available user
surface. Exact v0.1.1 runtime revision
`8867c46774c693a335853625dd967fd3520976ff` already had green protected-main CI
and reviewed free-model OpenRouter acceptance; the final evidence commit must
repeat both exact-commit gates. The tag-protected signing Environment had its
Pages URL but no production fingerprint or secret-subkey export.

## Requirement evidence

| # | Ordinary-user outcome | Authoritative evidence | Current conclusion |
| --- | --- | --- | --- |
| 1 | Obtain an attested package without Rust | `packaging/install-release.sh` verifies exact release-workflow Sigstore bundles and complete checksums; native packages and `packaging/build-signed-linux-repositories.sh` cover APT, DNF, and Pacman; package/repository clean-install tests cover every qualified family. | **v0.1.0 archives are publicly attested; the onboarding/repository experience is public-release gated.** No source checkout or older tag can substitute for the first qualifying onboarding tag and public repository acceptance. |
| 2 | Run one guided command | Bare terminal `mealyctl` selects onboarding for an unconfigured private home and a new chat for a configured home; `mealyctl onboard` composes provider selection, reviewed activation, service installation/start, health, `doctor`, and chat. A PTY process proof covers both bare-command journeys and proves non-terminal use fails without mutation. The verified interactive bootstrap hands off to the same installed command. The implicit private home is the stable `$HOME/.mealy`, not a directory-relative `.mealy`, and a process proof reuses it after changing working directories. | **Source-ready and process-tested.** |
| 3 | Choose free, subscription, local, custom, or advanced API routes without researching accounting | The `OnboardRouteArgument` command surface and provider-configuration process tests cover strict free OpenRouter, authenticated custom Responses, credentialless loopback, the official Codex subscription client, OpenAI API, and Anthropic API. The ChatGPT route uses bounded official app-server account/login/model methods: terminal users separately consent to browser or headless device login when needed, then onboarding selects the unique account-catalog default or validates an exact override. Mealy retains a conservative 128,000-token context ceiling without asking the user for internal model metadata. Browser/device, signed-in, non-terminal, decline, and missing-client process proofs cover credential containment, official prerequisite guidance, and no-mutation behavior; a live model-call-free run selected the installed Plus account's `gpt-5.6-sol` default. Claude subscription routing is excluded because Anthropic's current third-party terms prohibit it; legacy names fail before mutation/invocation and direct Anthropic API, OpenRouter, custom, or Claude Code alternatives are reported. Catalog routes derive limits/prices; advanced routes require explicit conservative values. When a remote route's named environment variable is absent, terminal onboarding captures one bounded credential with echo disabled, restores echo before the next prompt, and reuses the same zeroizing value through discovery/probe/broker activation. PTY tests cover OpenRouter and custom endpoints; non-terminal absence fails before mutation. | **Source-ready, process-tested, and live account/catalog accepted.** OpenRouter free remains subject to exact live acceptance for publication. |
| 4 | See a bounded live route probe pass | Onboarding calls the existing byte-, event-, identity-, timeout-, and model-bounded provider probes before activation. Provider process tests cover each protocol and redaction; the private custom endpoint has separate live acceptance. | **Source-ready.** The release still requires reviewed free-OpenRouter live evidence. |
| 5 | Have the owner service installed and running | `scripts/systemd-service-smoke.sh` starts from a clean home, uses the real generated enabled systemd user unit, requires health plus sandbox-conformant `doctor`, and executes a governed mutation. Protected Linux CI prepares a clean user manager with lingering enabled. The tag workflow repeats the proof from the exact public rootless download before accepting a release. | **Source-ready and installed-service tested; first qualifying public tag remains required.** |
| 6 | Reach the first useful chat | The same installed-service journey drives onboarding through a real terminal input, requires the visible model response, verifies exact usage, and finds the committed durable task before accepting success. Public acceptance uses the downloaded installer without a repository override and reruns this journey through first chat, restart, `doctor`, durable continuation, and uninstall. | **Source-ready and end-to-end tested; first qualifying public tag remains required.** |
| 7 | Restart and resume | `chat --continue` selects the newest exact-binding session without creating another, while `chat --pick` provides a bounded terminal-only chooser for 20 recent exact-binding sessions and resumes only the selected one. The systemd journey captures the enabled installed service and its PID, restarts it, requires a distinct healthy daemon and passing `doctor`, then resumes the exact prior session and rechecks the one-session inventory. Login-manager lingering plus the generated enabled unit cover boot activation under the supported distro contract. | **Implemented; exact protected systemd acceptance is required on every revision.** A hosted runner cannot reboot its physical host, so Mealy proves the controllable cold-process, durable-state, enabled-unit, and distro-contract components instead of claiming a literal hardware reboot occurred in CI. |
| 8 | Diagnose a failure with one command | `mealyctl doctor` checks API readiness, SQLite startup integrity, permissions, required system executables, and enforceability of every sandbox profile; onboarding will not report completion until it passes. | **Source-ready and package-tested.** |
| 9 | Update and roll back without losing state | `install-status`, no-mutation `update`, restartable approved archive update, pre-update backup, qualification, automatic same-schema slot rollback, repair, uninstall, and native manager handoffs are implemented. Installed failure injection requires the prior package, health, `doctor`, backup, and durable task to survive. | **Source-ready and installed-package tested.** |
| 10 | Find the same short, version-matched workflow | `GETTING_STARTED.md` is bundled in every archive/native package. The signed repository landing page carries distro install, onboarding, continuation, diagnostics, update, fingerprint, and version-tagged detailed links inside the complete signed repository inventory. Documentation validation binds public CLI/API surfaces and local links. | **Source-ready and package/repository tested, not deployed.** The configured public URL currently returns HTTP 404. |

## Failure-behavior audit

The composed path also has direct negative evidence:

- credential values are imported once from the named environment variable or, only on terminal
  stdin/stderr, captured through an echo-disabled bounded prompt; they are excluded from plans,
  config, service environments, the supported official Codex subscription client, and diagnostics;
- a required shared Codex login starts only after separate terminal consent; signed-out automation
  and explicit decline start no login and mutate no Mealy state, while completed Codex login is
  accurately disclosed as external state that a later Mealy-plan cancellation does not undo;
- the free OpenRouter route admits only exact `:free`, tool/text-capable catalog entries whose
  complete token and auxiliary prices are zero;
- an existing `config.json` is never replaced without `--reconfigure` while stopped;
- service-start or bounded readiness failure preserves the configured home and reports the
  completed boundary;
- `--configure-only` makes an intentionally unstarted home explicit; and
- implicit state resolves to one absolute owner home across working directories, while absent or
  invalid `HOME` fails with an actionable override instead of creating state in the current
  directory;
- a bare invocation requires all three terminal streams, selects its journey only from a
  no-follow regular `config.json`, and requires explicit subcommands for automation;
- owner-service removal stops the still-reviewed loaded unit before disabling its links, avoiding
  the linked-unit `disable --now` ordering failure in systemd 257 while retaining systemd 255
  behavior; and
- release install, onboarding, service operations, provider activation, and update transactions
  either reuse stable identities or report their durable completion evidence.

## Remaining gates before the goal is publicly true

1. The exact v0.1.1 candidate must complete its uninterrupted 24-hour soak and pass the checked
   report validator.
2. Final release archives and native packages must be rebuilt from the promoted subject and pass
   protected release/package acceptance.
3. An owner-reviewed, exact-zero-price OpenRouter run must pass against the promoted commit.
4. The owner must supply the offline-controlled production repository identity, fingerprint, and
   encrypted signing-subkey export; CI must not invent that trust root.
5. The onboarding stack must be merged through protected CI into a subsequent qualifying release,
   or be deliberately selected for the current release only if its exact release subject and soak
   are rebuilt and repeated.
6. The tag workflow must publish immutable attested assets, deploy the signed repositories, and
   pass clean public HTTPS bootstrap plus APT/DNF/Pacman acceptance.

Until those gates are satisfied, the implementation is a protected-green candidate experience,
not a production release available to everyone.
