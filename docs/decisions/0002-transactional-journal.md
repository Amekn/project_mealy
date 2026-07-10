# ADR 0002: Canonical tables plus an atomic transition journal

Status: Accepted

## Context

Mealy needs current-state queries, scheduling, audit history, resumable timelines, and debug replay. Pure event sourcing makes all old event schemas part of executable reconstruction forever. Mirror-file designs create two authorities. OpenCode's event transition and Hermes' SQLite/JSON split both expose these costs.

## Decision

Maintain normalized canonical SQLite tables and an immutable transition journal. Every application transition updates canonical state and appends its event and outbox rows in one transaction. Derived read models may be rebuilt; canonical state is migrated explicitly.

The journal supports audit, streaming, causation, and recorded-result replay. It is not the only mechanism by which the latest software version can construct all current tables.

## Consequences

- State and history cannot drift when mutation rules are followed.
- Operational queries remain direct and indexed.
- Migrations must update canonical tables and preserve journal readability.
- Debug replay simulates recorded facts; it is not a general state-rebuild engine.
