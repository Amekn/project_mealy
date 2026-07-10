# mealy-api

Authenticated command/query/timeline adapter. It validates transport input, resolves a principal, calls application use cases, and projects safe DTOs. It contains no agent loop or direct database access.

The HTTP server is intentionally not implemented in the architecture-baseline commit.
