# mealyd

Trusted daemon composition root. It owns validated configuration and rollback history,
backup-aware migration/recovery startup, adapter wiring, supervision, readiness, safe mode,
operational maintenance, and bounded graceful/forced drain evidence.

It must not contain domain transition logic or run model-proposed commands in process.
