# Release summaries

Every stable tag must have a short human-facing summary named `vX.Y.Z.md`.
The release workflow inserts that checked file into the immutable GitHub release
notes before the machine-verifiable acceptance evidence.

Keep each summary focused on observable user and operator changes:

- supported installation and operating-system surfaces;
- new, changed, or removed commands and workflows;
- provider, security, migration, and compatibility changes; and
- known limits that affect an upgrade decision.

Do not copy generated soak measurements, workflow URLs, checksums, or
attestation details into these files. The release renderer derives those from
the exact qualified tag and checked evidence.
