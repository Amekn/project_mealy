# mealy-protocol

Versioned external DTOs for HTTP/SSE and future transports. Domain structs are not serialized directly as API contracts unless deliberately wrapped here.

Compatibility rules:

- additive fields must have safe defaults;
- removals or semantic changes require a new API/schema version;
- event cursors are opaque to clients;
- unknown event types must not crash clients.
