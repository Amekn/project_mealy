# mealy-infrastructure

Concrete adapters for application ports. The SQLite adapter now provides the Phase 0 schema,
file-backed WAL/foreign-key/durability configuration, atomic task transitions, and the first Phase 1
session/input-admission transaction. Exact duplicate deliveries return their original receipt;
changed retries, forged ownership, and late transaction failures fail without partial writes.

Future modules will hold artifacts, process supervision, sandbox backends, provider clients, secret brokers, and extension RPC. Business transition rules do not belong here.
