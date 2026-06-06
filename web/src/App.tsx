import { useEffect, useState } from "react";
import { getHealth, type HealthResponse } from "./api";

type LoadState =
  | { kind: "loading" }
  | { kind: "ready"; health: HealthResponse }
  | { kind: "error"; message: string };

export function App() {
  const [state, setState] = useState<LoadState>({ kind: "loading" });

  useEffect(() => {
    let cancelled = false;

    getHealth()
      .then((health) => {
        if (!cancelled) {
          setState({ kind: "ready", health });
        }
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          const message = error instanceof Error ? error.message : "unknown error";
          setState({ kind: "error", message });
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <main className="shell">
      <aside className="sidebar">
        <div className="brand">Mealy</div>
        <nav aria-label="Primary">
          <a aria-current="page" href="#tasks">
            Tasks
          </a>
          <a href="#approvals">Approvals</a>
          <a href="#memory">Memory</a>
          <a href="#health">Health</a>
        </nav>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <h1>Task Timeline</h1>
            <p>Local daemon workspace</p>
          </div>
          <DaemonStatus state={state} />
        </header>

        <section className="panel" id="tasks">
          <div className="panel-header">
            <h2>Active Work</h2>
            <button type="button">New Task</button>
          </div>
          <div className="empty-state">No active tasks yet.</div>
        </section>
      </section>
    </main>
  );
}

function DaemonStatus({ state }: { state: LoadState }) {
  if (state.kind === "loading") {
    return <span className="status muted">Checking daemon</span>;
  }

  if (state.kind === "error") {
    return <span className="status error">Daemon offline</span>;
  }

  return <span className="status ready">{state.health.status}</span>;
}
