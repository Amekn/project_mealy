# Security Policy

Mealy is currently an architecture baseline, not a production-ready agent. The placeholder binaries
do not yet execute models or tools. Do not rely on this repository to isolate untrusted code until
the sandbox, policy, secret-broker, and process-boundary phases are implemented and verified.

The normative security requirements are in [`REQUIREMENTS.md`](REQUIREMENTS.md), and the working
threat model is in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Reporting a vulnerability

Do not open a public issue containing an exploit, secret, or sensitive machine data. Use GitHub's
private vulnerability-reporting feature for this repository when available; otherwise contact the
repository owner privately through the contact method on their GitHub profile.

Include the affected revision, operating system, reproduction steps, impact, and any evidence that
the behavior crosses a stated trust boundary. Never include live credentials.
