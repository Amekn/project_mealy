use axum::{Json, Router, routing::get};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
}

pub fn router() -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(readiness))
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "mealyd",
    })
}

async fn readiness() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ready",
        service: "mealyd",
    })
}
