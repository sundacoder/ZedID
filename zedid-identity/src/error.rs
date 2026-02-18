use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("Invalid SPIFFE ID: {0}")]
    InvalidSpiffeId(String),

    #[error("SVID expired for workload: {0}")]
    SvidExpired(String),

    #[error("JWT validation failed: {0}")]
    JwtValidationFailed(String),

    #[error("Identity not found: {0}")]
    NotFound(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}
