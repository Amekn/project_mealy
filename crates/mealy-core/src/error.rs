use thiserror::Error;

pub type Result<T, E = MealyError> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum MealyError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("policy denied: {0}")]
    PolicyDenied(String),
    #[error("invalid state transition: {0}")]
    InvalidTransition(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("external provider error: {0}")]
    Provider(String),
    #[error("tool execution error: {0}")]
    Tool(String),
}
