# Rust Crates

The Rust workspace is split by architectural boundary, not by implementation convenience.

- `mealy-core`: shared IDs, timestamps, errors, and primitive runtime types.
- `mealy-events`: append-only event envelope and event metadata.
- `mealy-store`: event/projection storage interfaces and storage implementations.
- `mealy-task`: task, session, run, approval, and validation state models.
- `mealy-policy`: security profiles, risk classes, policy requests, and decisions.
- `mealy-platform`: cross-platform paths, service, process, and secret abstractions.
- `mealy-api`: stable API DTOs shared by clients and the daemon.
- `mealy-server`: local HTTP API server.
- `mealy-artifacts`: artifact metadata and artifact store interfaces.
- `mealy-provider`: LLM provider interfaces and normalized responses.
- `mealy-tools`: tool capabilities, tool requests, and broker-facing traits.
- `mealy-agent`: Mealy-native agent runtime interfaces.
- `mealy-context`: context bundles and provenance model.
- `mealy-memory`: governed memory records and memory lifecycle types.
- `mealy-plugin`: plugin manifests and host-facing plugin contracts.
- `mealy-testkit`: fakes and fixtures for integration and scenario tests.
