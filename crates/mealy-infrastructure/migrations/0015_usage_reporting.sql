CREATE INDEX run_terminal_completion_idx
    ON run(completed_at_ms, id)
    WHERE status IN ('succeeded', 'failed', 'cancelled');
