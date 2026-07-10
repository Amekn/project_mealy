# Mealy Documentation

Start with these documents in order:

1. [`../REQUIREMENTS.md`](../REQUIREMENTS.md) — normative product and system requirements.
2. [`../ARCHITECTURE.md`](../ARCHITECTURE.md) — component boundaries and runtime design.
3. [`THREAT_MODEL.md`](THREAT_MODEL.md) — assets, actors, boundaries, and abuse cases.
4. [`DOMAIN_MODEL.md`](DOMAIN_MODEL.md) — IDs, lifecycles, and transition rules.
5. [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) — vertical delivery phases and exit gates.
6. [`TESTING.md`](TESTING.md) — verification strategy and crash matrix.
7. [`decisions/`](decisions/) — accepted architectural choices.
8. [`research/`](research/) — pinned evidence from the eight reference systems.

Requirements are authoritative for product intent. Accepted ADRs are authoritative for cross-cutting implementation decisions. Architecture describes the current synthesis and must be updated when an ADR supersedes it.

Documentation changes that alter a requirement or invariant should include the corresponding test or implementation-plan change.
