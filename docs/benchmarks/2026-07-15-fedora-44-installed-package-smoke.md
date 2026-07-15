# Fedora 44 rootless archive acceptance — 2026-07-15

This is pre-release, same-host runtime evidence for the exact x86_64 binaries under the current
24-hour soak. It is not an attestation, not a published-tag observation, and not a substitute for
the final documentation-inclusive reproducible package and public-download gates.

## Subject

- Host: Fedora Linux 44 KDE, Linux `7.1.3-200.fc44.x86_64`, x86_64
- Filesystem: Btrfs
- glibc: 2.43
- Bubblewrap: 0.11.0
- systemd: 259.7
- Archive manifest commit: `c48394518f06892fce341eb91be5be0e24bfc2d6`
- Archive SHA-256:
  `ccad0fa0698f4c6aa4035a7b90dd7427dba3564225036bf13c4f7904ed3a0ed5`
- Checksum-manifest SHA-256:
  `b0f5397087a411c8f1d25733f796eb86d95739a3130e16ca908cac0062aaeece`
- Installer SHA-256:
  `988b684dac5c919ef30e8c2c23004fadde9909fbe8d146f94b304dad210da045`
- CycloneDX SBOM SHA-256:
  `c8407a576bd04ad4bbfad70102ade43f373eaa2268bc25f201019ade154ca7cd`
- `mealyd` SHA-256:
  `649db94894de63fb973c7d2ef7a4749100d5c9b3ca77524a0f8cbfde66c39572`
- `mealyctl` SHA-256:
  `e96d0012fb07b62d033d385257e3cc3a1c75f93d3a256a8804e213405c2dcf90`

Two independent archive assemblies were byte-identical. The daemon and client hashes exactly match
the external release binaries selected for the running soak. The archive predates the final soak
report and therefore cannot be promoted unchanged as the public release.

## Command

The repository's public installed-package harness was run with sandbox enforcement mandatory:

```sh
MEALY_INSTALLED_SMOKE_REQUIRE_SANDBOX=true \
MEALY_INSTALLED_SMOKE_ROOT="$PWD/target" \
scripts/installed-package-smoke.sh \
  target/release-validation-c483945/dist-a/mealy-v0.1.0-linux-x86_64-gnu.tar.gz \
  target/release-validation-c483945/dist-a/SHA256SUMS \
  target/release-validation-c483945/dist-a/install-mealy.sh
```

## Result

The harness exited zero and reported:

```text
installed package smoke: ok (version 0.1.0, schema 15, task 019f6341-6b3f-7a32-93ed-ac949da821c8)
```

It independently verified the outer checksum binding, archive and payload inventories, manifest,
binary version/schema identity, complete packaged documentation, and executable modes. It then
installed into an empty owner-local prefix and state home without root or a Rust toolchain,
generated the hardened systemd-user unit, and required `doctor` to report both `observe` and
`workspace_write` sandbox profiles enforceable.

The installed daemon completed one durable task, settled all reservations, reproduced its result
through recorded-only replay with zero live provider/tool calls, returned a valid one-day usage
projection, created and isolated-verified a secret-free backup, drained within its bound, and
exited cleanly. Uninstall removed only managed program files and retained `mealy.sqlite3`.

This adds Fedora-family evidence for the rootless archive path. Debian packages remain native
Debian-format assets; the final tag must still repeat archive acceptance on native x86_64 and
ARM64 runners and prove the tokenless public bootstrap against only downloaded release assets.
