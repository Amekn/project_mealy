//! Testable standalone entry point for Mealy's in-sandbox MCP stdio launcher.

fn main() {
    let _code = mealy_infrastructure::mcp_stdio_launcher_main();
    std::process::exit(70);
}
