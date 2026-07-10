# ADR 0004: OS sandboxing and out-of-process extensions

Status: Accepted

## Context

Hermes, OpenCode, Pi, and OpenClaw explicitly distinguish approval/policy heuristics from real isolation. Their plugins commonly execute with full process authority. Mealy ingests untrusted model and external content and will eventually support remote channels.

## Decision

The model is untrusted. Shell and filesystem mutation execute outside the daemon under an enforceable profile. Third-party extensions run in supervised processes with manifest-declared capability grants. Secrets are brokered per invocation and are not ambient worker environment.

If the host cannot enforce a requested profile, execution fails closed or requires an explicit recorded downgrade to full-trust mode.

## Consequences

- Cross-platform adapters and `doctor` capability reporting are first-order work.
- Third-party extension development uses RPC rather than direct library calls.
- A policy allow does not bypass the sandbox.
- First-party compiled adapters may remain in the daemon when their trust is explicit.
