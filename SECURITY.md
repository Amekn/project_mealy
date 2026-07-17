# Security Policy

Mealy is active pre-1.0 software. The binaries execute model requests and governed
tools, persist durable personal-agent state, broker credentials, and can mediate external effects.
Treat only a non-draft, non-prerelease GitHub release whose exact tag workflow and dependent public
acceptance jobs completed successfully as an attested production release. Never treat an arbitrary
checkout or development archive as one.

The supported production worker boundary is a single-owner Linux host whose `mealyctl doctor`
report marks the required sandbox profiles enforceable. macOS is a packaged control-plane preview but
does not currently provide the claimed native worker isolation. Windows is outside the release-one
support and CI contract. Keep the daemon API on its authenticated loopback listener; Mealy is not a
multi-tenant or public-internet service.

Model, web, channel, skill, MCP, browser, attachment, and memory content is untrusted even after
authentication. Only explicitly configured capabilities and exact approval/effect boundaries grant
authority. Do not work around a fail-closed sandbox, digest, ownership, recovery, or readiness
error. Preserve the home and its SQLite sidecars when reporting possible corruption or an unknown
external effect.

Never place the Mealy home inside a workspace or extension mount. Current builds reject the home,
its descendants, and any containing root, and also refuse to attach a local text file from private
daemon state. Treat any older build that permits such overlap as capable of disclosing bearer or
broker material to model context.
Keep custom homes outside source checkouts as well. Repository ignore rules cover the default
`.mealy/` directory and SQLite/WAL/SHM filenames as accident prevention, but they are not a
security boundary and cannot safely enumerate every broker or channel-secret file.

Keep the production Mealy home on a persistent local filesystem outside `/tmp` and `/var/tmp`.
Linux service installation rejects those private-temporary hierarchies and `tmpfs`/`ramfs` homes;
working around that check can make state invisible to the unit or disposable at reboot.

The normative security requirements are in [`REQUIREMENTS.md`](REQUIREMENTS.md), and the working
threat model is in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Supported versions

Supported versions are the non-draft, non-prerelease entries on the repository's GitHub Releases
page whose exact tag workflow and dependent public-acceptance jobs completed successfully. Security
fixes are developed on the reviewed `main` branch and become release claims only after that workflow
publishes attested x86_64 and ARM64 Linux assets. Development snapshots receive no compatibility or
response-time guarantee.

## Reporting a vulnerability

Do not open a public issue containing an exploit, secret, or sensitive machine data. Use GitHub's
private vulnerability-reporting feature for this repository when available; otherwise contact the
repository owner privately through the contact method on their GitHub profile.

Include the affected revision, operating system, reproduction steps, impact, and any evidence that
the behavior crosses a stated trust boundary. State whether the home can be preserved for forensic
inspection and whether any effect remains `outcome_unknown`. Never include live credentials,
private attachment contents, broker files, bearer tokens, or an unredacted home archive.
