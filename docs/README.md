# Mealy Documentation

Start with these documents in order:

1. [`GETTING_STARTED.md`](GETTING_STARTED.md) — verified install, provider choice, one-command
   onboarding, and first chat.
2. [`QUICKSTART.md`](QUICKSTART.md) — comprehensive setup, capabilities, and limitations.
3. [`LINUX_SUPPORT.md`](LINUX_SUPPORT.md) — qualified distributions, derivatives, and host boundaries.
4. [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md) — current blockers and competitive acceptance gates.
5. [`../REQUIREMENTS.md`](../REQUIREMENTS.md) — normative product and system requirements.
6. [`../ARCHITECTURE.md`](../ARCHITECTURE.md) — component boundaries and runtime design.
7. [`THREAT_MODEL.md`](THREAT_MODEL.md) — assets, actors, boundaries, and abuse cases.
8. [`DOMAIN_MODEL.md`](DOMAIN_MODEL.md) — IDs, lifecycles, and transition rules.
9. [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) — vertical phases and exit gates.
10. [`TESTING.md`](TESTING.md) — verification strategy and crash matrix.
11. [`API.md`](API.md) — authenticated local HTTP/JSON and SSE compatibility reference.
12. [`CLI.md`](CLI.md) — source-checked owner command surface and usage conventions.
13. [`CI_CD.md`](CI_CD.md) — developer checks and protected source-to-production promotion.
14. [`OPERATIONS.md`](OPERATIONS.md) — install, diagnostics, backup, retention, and recovery.
15. [`RELEASE.md`](RELEASE.md) — attested packages, clean install, upgrade, and rollback.
16. [`REQUIREMENTS_COVERAGE.md`](REQUIREMENTS_COVERAGE.md) — release evidence for normative groups.
17. [`decisions/`](decisions/) — accepted architectural choices.
18. [`research/REFERENCE_SYSTEMS.md`](research/REFERENCE_SYSTEMS.md) — pinned architectural
    evidence from the eight reference systems.
19. [`research/PRODUCT_OPERATIONS_BENCHMARK_2026-07-24.md`](research/PRODUCT_OPERATIONS_BENCHMARK_2026-07-24.md)
    — current install, onboarding, maintenance, documentation, CI, release, and user-experience
    comparison.
20. [`benchmarks/`](benchmarks/) — versioned soak/performance reports and reproduction commands.

Requirements are authoritative for product intent. Accepted ADRs are authoritative for cross-cutting implementation decisions. Architecture describes the current synthesis and must be updated when an ADR supersedes it.

Documentation changes that alter a requirement or invariant should include the corresponding test or implementation-plan change.
