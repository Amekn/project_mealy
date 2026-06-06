# project_mealy
Mealy is a the personal AI assistant that is actually realiable and do the work. The name from the a 'mealy machine', which is a finite-state machine whose output values are determined by both its current state and the current inputs.

## Workspace

Mealy is now scaffolded as a Rust workspace plus a separate TypeScript web UI.

```text
apps/
  mealyd/       local daemon
  mealyctl/     administration CLI
  mealy-tui/    optional terminal UI
crates/
  mealy-*/      runtime, policy, storage, agent, provider, and plugin crates
web/
  TypeScript React UI over the mealyd API
migrations/
schemas/
tests/scenarios/
```

Useful commands:

```sh
cargo check --workspace
cargo run -p mealyd
cargo run -p mealyctl -- doctor
cd web && npm install && npm run dev
```

## License
Source-available for viewing only. See LICENSE. I'm keeping options open to open-source this properly in the future once the project is more mature.
