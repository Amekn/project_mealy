# mealy-application

Application use cases and ports. This crate coordinates domain transitions but does not know SQLite, HTTP, provider SDKs, or platform sandbox commands.

Modules should align to use cases (`admit_input`, `claim_work`, `dispatch_effect`) rather than becoming generic manager/service buckets.

Current proof:

- injectable clock and typed ID generation ports;
- authenticated session ownership context;
- bounded session creation and durable, idempotent input-admission use cases;
- a storage port that requires canonical session/inbox state, journal facts, and acknowledgements to
  commit atomically.
