# Applications

Applications are composition roots. They may select concrete adapters and process lifecycle, but business rules belong in `mealy-application` and `mealy-domain`.

- `mealyd`: trusted long-running daemon.
- `mealyctl`: local API client; it must not open the daemon database directly.
