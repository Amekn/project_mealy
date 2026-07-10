//! Mealy's long-running daemon entry point.

fn main() {
    let config = mealy_api::ApiConfig::default();
    assert!(
        config.is_loopback(),
        "default API listener must be local-only"
    );
    println!("mealyd architecture baseline; runtime implementation has not started");
}
