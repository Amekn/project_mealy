# ADR 0008: Risk-based independent validation

Status: Accepted

## Context

Codex Guardian, Vercel evaluator-optimizer patterns, Eve evals, and fresh-worker verification demonstrate value in independent review. Requiring a second model for every conversational answer would add cost and latency without proportional evidence.

## Decision

All tasks declare success criteria. Deterministic checks are preferred. Medium- and high-risk work receives a fresh, normally read-only validation run with its own context manifest and task-specific rubric. Low-risk work may complete on deterministic checks alone. Waivers are durable policy decisions.

## Consequences

- Validation is a domain object with evidence, not a prompt suffix.
- Risk classification becomes part of task admission and policy.
- Validators cannot silently fix producer output; revisions create new producer attempts.
- Cost remains proportional while high-impact results receive independent scrutiny.
