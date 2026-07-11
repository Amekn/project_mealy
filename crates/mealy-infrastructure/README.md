# mealy-infrastructure

Concrete adapters for application ports. The SQLite adapter owns migrations 1–11, WAL/foreign-key
durability, every canonical transaction, journal/timeline/outbox projections, fencing/recovery,
memory/FTS, validation/delegation, extension/channel evidence, and operational inspection. File
adapters provide content-addressed artifacts, encrypted complete backups, complete/scoped exports,
forensics, secret brokerage, and safe GC. Process adapters provide Bubblewrap tool and extension
workers with exact executable/runtime identity.

Exact duplicates return original receipts; ownership, capacity, stale fences, changed retries,
unsafe paths, and late transaction failures fail without partial canonical writes. Business
transition rules do not belong here.
