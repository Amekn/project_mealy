# mealy-testkit

Deterministic clock, ID, fake provider/executor, crash-injection, and scenario helpers. Production crates must never depend on this crate.

The current foundation includes a manually advanced clock and a thread-safe repeatable UUIDv7 ID
generator that implement the application ports.
