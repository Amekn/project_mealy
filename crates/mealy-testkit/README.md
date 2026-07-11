# mealy-testkit

Deterministic clock, ID, fake provider/executor, crash-injection, and scenario helpers. Production crates must never depend on this crate.

It includes a manually advanced clock, thread-safe repeatable UUIDv7 generator, scripted normalized
provider with cancellation/request capture, bounded fixture resources/tools, and deterministic
helpers used by storage, process, replay, recovery, and validation suites.
