# mealy-api

Authenticated bounded HTTP/SSE command, query, timeline, signed-ingress, and administration
adapter. It validates transport input, resolves a principal and active channel binding, calls the
backend/application boundary, projects safe versioned DTOs, propagates request IDs, limits command
and subscriber concurrency, and exposes resumable gap-aware event streams.

It contains no agent loop, policy transition logic, provider dispatch, or direct database access.
