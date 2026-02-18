use anyhow::Result;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    /// SPIFFE trust domain
    pub trust_domain: String,
    /// TARS endpoint URL
    pub tars_endpoint: String,
    /// TARS API key (optional)
    pub tars_api_key: Option<String>,
    /// JWT signing secret
    pub jwt_secret: String,
    /// JWT issuer
    pub jwt_issuer: String,
    /// Database URL (SQLite for prototype, PostgreSQL for production)
    #[allow(dead_code)]
    pub database_url: String,
    /// Server port
    pub port: u16,
}

impl AppConfig {
    pub fn load() -> Result<Self> {
        // Load from environment variables with defaults for prototype
        dotenvy::dotenv().ok();

        Ok(Self {
            trust_domain: std::env::var("ZEDID_TRUST_DOMAIN")
                .unwrap_or_else(|_| "tetrate.io".to_string()),
            tars_endpoint: std::env::var("TARS_ENDPOINT")
                .unwrap_or_else(|_| "simulation://tars.tetrate.io".to_string()),
            tars_api_key: std::env::var("TARS_API_KEY").ok(),
            jwt_secret: std::env::var("ZEDID_JWT_SECRET")
                .unwrap_or_else(|_| "zedid-dev-secret-change-in-production-please".to_string()),
            jwt_issuer: std::env::var("ZEDID_JWT_ISSUER")
                .unwrap_or_else(|_| "zedid.tetrate.io".to_string()),
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "sqlite::memory:".to_string()),
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()
                .unwrap_or(8080),
        })
    }
}
