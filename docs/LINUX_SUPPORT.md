# Linux support contract

Mealy production releases target GNU/Linux only. Support means that the published package for an
exact tag passed its native package-manager lifecycle, daemon conversation/replay/drain smoke,
Bubblewrap enforcement probe, protected CI, live-provider acceptance, and attested public-download
verification. A source checkout or a package built outside that workflow is not release evidence.

## Qualified distributions

| Distribution | Qualified releases | Architectures | Preferred package | Generic archive |
| --- | --- | --- | --- | --- |
| Ubuntu | 24.04 LTS and 26.04 LTS | x86-64, ARM64 | `.deb` | yes |
| Debian | 13 (`trixie`) | x86-64, ARM64 | `.deb` | yes |
| Fedora Linux | 44 | x86-64, ARM64 | `.rpm` | yes |
| Arch Linux | digest-pinned rolling image current at release qualification | x86-64 | `.pkg.tar.zst` | yes |

Arch Linux upstream is an x86-64 distribution. Arch Linux ARM is a separate derivative and is not
an official Mealy production target. The ARM64 generic archive and Fedora/Debian-family packages
do not imply that an Arch ARM package has been tested.

Ubuntu 24.04 remains qualified alongside 26.04 because both are active LTS releases and 24.04
provides the oldest supported glibc baseline. Debian 13 is the supported Debian stable line.
Fedora and Arch are re-qualified against pinned clean images for each release because their base
systems move more quickly.

## Host requirements

Every production host must provide all of these boundaries:

- x86-64 or ARM64 Linux with glibc 2.39 or newer; musl-only systems are not compatible with the
  published binaries;
- a kernel that implements the `openat2` confinement used for workspace access and permits
  unprivileged user namespaces for the dedicated Bubblewrap policy;
- root-controlled regular executables at `/usr/bin/bwrap` and `/usr/bin/ldd`;
- Bubblewrap capable of creating user, PID, mount, IPC, UTS, and network namespaces without being
  setuid;
- persistent local storage for the private Mealy home, with normal SQLite locking and atomic rename
  semantics;
- a systemd user manager for the supported background-service workflow.

Running `mealyd` in the foreground is valid on an otherwise conforming non-systemd host, but Mealy
does not claim production service supervision there. The generated service deliberately delegates
tool isolation to per-call Bubblewrap profiles; replacing it with a container or a different
supervisor requires a separate security review.

After installation, this is the authoritative host decision:

```sh
mealyctl --home "$HOME/.mealy" setup
mealyd --home "$HOME/.mealy" &
mealyctl --home "$HOME/.mealy" doctor
```

Do not enable tools if `doctor` reports that `observe` or `workspace_write` is not `enforceable`.
Stop the daemon with `mealyctl --home "$HOME/.mealy" drain` before changing stopped-home
configuration.

## Derivative distributions

Derivatives are expected to work only when they retain the complete contract above. They are a
compatibility tier, not an automatic support promise, because derivatives commonly change the
exact controls Mealy depends on:

- Debian and Ubuntu derivatives may use the `.deb` when their package dependencies resolve and
  their glibc is at least 2.39. A derivative can replace Ubuntu's AppArmor policy or disable user
  namespaces, so the Bubblewrap probe and `doctor` still decide.
- Fedora derivatives may use the `.rpm` when they retain Fedora-compatible RPM dependency names,
  `/usr/bin/bwrap`, SELinux/user-namespace behavior, and glibc 2.39 or newer. Older RHEL-family
  releases with glibc older than 2.39 are incompatible even if RPM accepts the file.
- Arch derivatives may use the x86-64 package when they track current Arch package conventions and
  preserve systemd, glibc, Bubblewrap, and `/usr` layout. Immutable systems such as SteamOS should
  use the owner-local generic archive; modifying their read-only base image is not supported.

Known non-targets include Alpine and other musl-only systems, NixOS's non-FHS executable layout,
Android, WSL, minimal containers without the required namespaces, and immutable images that cannot
provide the trusted `/usr/bin` helpers. A derivative that fixes these boundaries can use the
generic archive, but it remains unqualified until its exact environment joins protected CI.

## Package behavior

All native packages install immutable program material beneath `/usr/lib/mealy/release`, expose
`/usr/bin/mealyd` and `/usr/bin/mealyctl`, and place offline documentation beneath
`/usr/share/doc/mealy`. They contain no maintainer script, install hook, service activation, user
creation, or home-directory mutation. Removing a package never deletes `$HOME/.mealy`.

The owner-local archive installs beneath `$HOME/.local` by default and is the portability and
rollback fallback across every qualified distribution. The optional browser remains x86-64-only;
ARM64 hosts retain the production daemon, providers, workspace tools, MCP, extensions, channels,
scheduling, and non-rendered web tools.

## Qualification cadence

A distribution remains in the production matrix only while its upstream release receives security
updates and the clean-host job remains green. Ubuntu and Debian are tested at their named release
line with current updates. Fedora advances one release at a time after a clean acceptance run.
Arch uses a digest-pinned rolling image and must be refreshed before each Mealy release.

Version references are based on the upstream [Ubuntu release list](https://wiki.ubuntu.com/Releases),
[Debian release index](https://www.debian.org/releases/),
[Fedora release announcement](https://fedoramagazine.org/announcing-fedora-linux-44/), and
[Arch Linux release model](https://archlinux.org/about/).
