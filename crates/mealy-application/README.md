# mealy-application

Application use cases and ports. This crate coordinates domain transitions but does not know SQLite, HTTP, provider SDKs, or platform sandbox commands.

Modules should align to use cases (`admit_input`, `claim_work`, `dispatch_effect`) rather than becoming generic manager/service buckets.

The implemented ports/use cases cover authenticated bounded admission and backpressure, promotion
and steering, fenced scheduling and concurrency policy, provider routing/attempts, typed tools,
effects and approvals, context/compaction, memory, validation/delegation, extensions/channels,
timeline/outbox/recovery, artifacts, and operational lifecycle evidence. Storage ports require
canonical state, journal facts, and required outbound notifications to commit atomically.
