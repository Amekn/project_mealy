# ADR 0003: Explicit unknown outcomes and idempotency-aware recovery

Status: Accepted

## Context

A worker or daemon can fail after an external service accepted a request but before Mealy recorded the response. Retrying may duplicate a payment, email, file write, or service mutation. Eve documents that an interrupted step re-runs; Pi's durability design correctly warns against retrying unfinished non-idempotent tools.

## Decision

Every effect declares `pure`, `idempotent`, `keyed`, or `non_idempotent` behavior and a recovery strategy. Mealy records intent and authorization before dispatch. Loss after dispatch becomes `outcome_unknown` unless the contract proves a safe retry.

Stable downstream idempotency keys derive from the Mealy effect ID. Unknown non-idempotent outcomes pause for reconciliation or explicit owner action.

## Consequences

- Recovery is honest and safe rather than cosmetically automatic.
- Tool authors must describe recovery and may need reconciliation adapters.
- The UI must surface unknown outcomes prominently.
- Some tasks will wait for a human instead of retrying.
