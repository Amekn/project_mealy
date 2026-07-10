# mealy-domain

Pure domain types and state machines. This crate must not depend on async runtimes, databases, filesystems, network clients, web frameworks, provider SDKs, or OS APIs.

Current proof:

- UUIDv7 typed identifiers;
- typed session input delivery modes;
- task lifecycle and validation gate;
- effect lifecycle and conservative recovery classification;
- generative task/effect lifecycle invariant tests.

Every public transition returns a fact that the application layer can journal.
