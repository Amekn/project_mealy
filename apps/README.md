# Rust Apps

- `mealyd`: the local daemon and source of truth.
- `mealyctl`: local administration CLI.
- `mealy-tui`: optional terminal UI client.

Applications should compose crates from `crates/`. Durable state and side effects stay behind the store, tool, and policy layers.
