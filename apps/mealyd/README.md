# mealyd

Trusted daemon composition root. It will own configuration, migration/recovery startup, adapter wiring, supervision, readiness, and graceful drain.

It must not contain domain transition logic or run model-proposed commands in process.
