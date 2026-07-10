# Cross-Crate Tests

- `integration/`: real SQLite and process-boundary tests that do not need a packaged daemon.
- `scenarios/`: black-box public-API flows, crash injection, recovery, and security cases.

Tests are named with requirement IDs. See [`../docs/TESTING.md`](../docs/TESTING.md).
