# Mealy Documentation

Start with these documents in order:

1. [`GETTING_STARTED.md`](GETTING_STARTED.md) — verified install, provider choice, one-command
   onboarding, and first chat.
2. [`QUICKSTART.md`](QUICKSTART.md) — comprehensive setup, capabilities, and limitations.
3. [`LINUX_SUPPORT.md`](LINUX_SUPPORT.md) — qualified distributions, derivatives, and host boundaries.
4. [`LINUX_REPOSITORIES.md`](LINUX_REPOSITORIES.md) — signed APT, DNF, and Pacman setup,
   independent verification, and maintainer key controls.
5. [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md) — current blockers and competitive acceptance gates.
6. [`../REQUIREMENTS.md`](../REQUIREMENTS.md) — normative product and system requirements.
7. [`../ARCHITECTURE.md`](../ARCHITECTURE.md) — component boundaries and runtime design.
8. [`THREAT_MODEL.md`](THREAT_MODEL.md) — assets, actors, boundaries, and abuse cases.
9. [`DOMAIN_MODEL.md`](DOMAIN_MODEL.md) — IDs, lifecycles, and transition rules.
10. [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) — vertical phases and exit gates.
11. [`TESTING.md`](TESTING.md) — verification strategy and crash matrix.
12. [`API.md`](API.md) — authenticated local HTTP/JSON and SSE compatibility reference.
13. [`CLI.md`](CLI.md) — source-checked owner command surface and usage conventions.
14. [`CI_CD.md`](CI_CD.md) — developer checks and protected source-to-production promotion.
15. [`OPERATIONS.md`](OPERATIONS.md) — install, diagnostics, backup, retention, and recovery.
16. [`RELEASE.md`](RELEASE.md) — attested packages, clean install, upgrade, and rollback.
17. [`REQUIREMENTS_COVERAGE.md`](REQUIREMENTS_COVERAGE.md) — release evidence for normative groups.
18. [`decisions/`](decisions/) — accepted architectural choices.
19. [`research/REFERENCE_SYSTEMS.md`](research/REFERENCE_SYSTEMS.md) — pinned architectural
    evidence from the eight reference systems.
20. [`research/PRODUCT_OPERATIONS_BENCHMARK_2026-07-24.md`](research/PRODUCT_OPERATIONS_BENCHMARK_2026-07-24.md)
    — current install, onboarding, maintenance, documentation, CI, release, and user-experience
    comparison.
21. [`research/ONBOARDING_COMPLETION_AUDIT_2026-07-24.md`](research/ONBOARDING_COMPLETION_AUDIT_2026-07-24.md)
    — direct evidence for each competitor-grade onboarding outcome and its remaining external
    release gates.
22. [`benchmarks/`](benchmarks/) — versioned soak/performance reports and reproduction commands.
23. [`releases/`](releases/) — checked human-facing changes included in each immutable release.

Requirements are authoritative for product intent. Accepted ADRs are authoritative for cross-cutting implementation decisions. Architecture describes the current synthesis and must be updated when an ADR supersedes it.

Documentation changes that alter a requirement or invariant should include the corresponding test or implementation-plan change.
