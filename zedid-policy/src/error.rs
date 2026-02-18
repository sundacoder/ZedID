use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("Policy validation failed: {0}")]
    ValidationFailed(String),

    #[error("Policy not found: {0}")]
    NotFound(String),

    #[error("Policy generation failed: {0}")]
    GenerationFailed(String),

    #[error("OPA evaluation error: {0}")]
    OpaError(String),

    #[error("TARS routing error: {0}")]
    TarsError(String),

    #[error("Policy conflict: {0}")]
    Conflict(String),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("HTTP error: {0}")]
    HttpError(String),
}
