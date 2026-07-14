//! Test/release-gate entry point for the fixed isolated browser worker.

fn main() -> std::process::ExitCode {
    mealy_infrastructure::browser_worker_main()
}
