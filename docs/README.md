# Mealy Documentation

Start with these documents in order:

1. [`QUICKSTART.md`](QUICKSTART.md) — prerequisites, release build, first run, and current limitations.
2. [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md) — current blockers and competitive acceptance gates.
3. [`../REQUIREMENTS.md`](../REQUIREMENTS.md) — normative product and system requirements.
4. [`../ARCHITECTURE.md`](../ARCHITECTURE.md) — component boundaries and runtime design.
5. [`THREAT_MODEL.md`](THREAT_MODEL.md) — assets, actors, boundaries, and abuse cases.
6. [`DOMAIN_MODEL.md`](DOMAIN_MODEL.md) — IDs, lifecycles, and transition rules.
7. [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) — vertical phases and exit gates.
8. [`TESTING.md`](TESTING.md) — verification strategy and crash matrix.
9. [`API.md`](API.md) — authenticated local HTTP/JSON and SSE compatibility reference.
10. [`CLI.md`](CLI.md) — source-checked owner command surface and usage conventions.
11. [`CI_CD.md`](CI_CD.md) — developer checks and protected source-to-production promotion.
12. [`OPERATIONS.md`](OPERATIONS.md) — install, diagnostics, backup, retention, and recovery.
13. [`RELEASE.md`](RELEASE.md) — attested packages, clean install, upgrade, and rollback.
14. [`REQUIREMENTS_COVERAGE.md`](REQUIREMENTS_COVERAGE.md) — release evidence for normative groups.
15. [`decisions/`](decisions/) — accepted architectural choices.
16. [`research/`](research/) — pinned evidence from the eight reference systems.
17. [`benchmarks/`](benchmarks/) — versioned soak/performance reports and reproduction commands.

Requirements are authoritative for product intent. Accepted ADRs are authoritative for cross-cutting implementation decisions. Architecture describes the current synthesis and must be updated when an ADR supersedes it.

Documentation changes that alter a requirement or invariant should include the corresponding test or implementation-plan change.
