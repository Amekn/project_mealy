# Mealy Documentation

Start with these documents in order:

1. [`QUICKSTART.md`](QUICKSTART.md) — prerequisites, release build, first run, and current limitations.
2. [`LINUX_SUPPORT.md`](LINUX_SUPPORT.md) — qualified distributions, derivatives, and host boundaries.
3. [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md) — current blockers and competitive acceptance gates.
4. [`../REQUIREMENTS.md`](../REQUIREMENTS.md) — normative product and system requirements.
5. [`../ARCHITECTURE.md`](../ARCHITECTURE.md) — component boundaries and runtime design.
6. [`THREAT_MODEL.md`](THREAT_MODEL.md) — assets, actors, boundaries, and abuse cases.
7. [`DOMAIN_MODEL.md`](DOMAIN_MODEL.md) — IDs, lifecycles, and transition rules.
8. [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) — vertical phases and exit gates.
9. [`TESTING.md`](TESTING.md) — verification strategy and crash matrix.
10. [`API.md`](API.md) — authenticated local HTTP/JSON and SSE compatibility reference.
11. [`CLI.md`](CLI.md) — source-checked owner command surface and usage conventions.
12. [`CI_CD.md`](CI_CD.md) — developer checks and protected source-to-production promotion.
13. [`OPERATIONS.md`](OPERATIONS.md) — install, diagnostics, backup, retention, and recovery.
14. [`RELEASE.md`](RELEASE.md) — attested packages, clean install, upgrade, and rollback.
15. [`REQUIREMENTS_COVERAGE.md`](REQUIREMENTS_COVERAGE.md) — release evidence for normative groups.
16. [`decisions/`](decisions/) — accepted architectural choices.
17. [`research/`](research/) — pinned evidence from the eight reference systems.
18. [`benchmarks/`](benchmarks/) — versioned soak/performance reports and reproduction commands.
19. [`releases/`](releases/) — checked human-facing changes included in each immutable release.

Requirements are authoritative for product intent. Accepted ADRs are authoritative for cross-cutting implementation decisions. Architecture describes the current synthesis and must be updated when an ADR supersedes it.

Documentation changes that alter a requirement or invariant should include the corresponding test or implementation-plan change.
