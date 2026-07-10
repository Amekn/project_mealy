# ADR 0006: Context manifests, epochs, and governed memory

Status: Accepted

## Context

All reviewed systems compact context; several persist summaries or memory. Few can prove item by item what a model saw, and automatic memory commonly trusts model extraction more than Mealy should.

OpenCode's context epochs and Codex/Pi compaction provenance are useful foundations. Vercel AI SDK's step-boundary message changes reinforce immutable in-flight requests.

## Decision

Persist an ordered context manifest for every model attempt. Pin baseline instructions and configuration in a versioned context epoch. Compaction is a derived, cited artifact and never deletes source history.

Long-term memory has a proposal/review/active/superseded/expired/deleted lifecycle with provenance, namespace, sensitivity, confidence, and retention. V1 uses SQLite and FTS5; embeddings are optional derived indexes.

## Consequences

- Debugging and privacy explanations become concrete.
- Storage cost increases; retention and artifact policies are required.
- Context compilation can be deterministic and unit tested.
- Memory quality can improve without making vector search authoritative.
