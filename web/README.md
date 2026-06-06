# Mealy Web

This is the TypeScript web UI. It is a thin client over the local `mealyd` API.

Run the daemon first:

```sh
cargo run -p mealyd
```

Then run the web app:

```sh
npm install
npm run dev
```

The Vite dev server proxies `/api/*` to `http://127.0.0.1:7341`.
