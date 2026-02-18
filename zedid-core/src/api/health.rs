use crate::state::AppState;
use axum::{extract::State, Json};
use serde::Serialize;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
    pub version: &'static str,
    pub timestamp: String,
}

#[derive(Serialize)]
pub struct SystemInfoResponse {
    pub service: &'static str,
    pub version: &'static str,
    pub trust_domain: String,
    pub tars_endpoint: String,
    pub tars_mode: String,
    pub capabilities: Vec<&'static str>,
    pub standards: Vec<&'static str>,
    pub timestamp: String,
}

pub async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy",
        service: "ZedID",
        version: env!("CARGO_PKG_VERSION"),
        timestamp: chrono::Utc::now().to_rfc3339(),
    })
}

pub async fn system_info(State(state): State<AppState>) -> Json<SystemInfoResponse> {
    let tars_mode = if state.config.tars_endpoint.contains("simulation") {
        "simulation (demo mode)"
    } else if state.config.tars_endpoint.contains("localhost") {
        "local-ollama"
    } else {
        "live-tars"
    };

    Json(SystemInfoResponse {
        service: "ZedID — Identity Dashboard & Policy Generator",
        version: env!("CARGO_PKG_VERSION"),
        trust_domain: state.config.trust_domain.clone(),
        tars_endpoint: state.config.tars_endpoint.clone(),
        tars_mode: tars_mode.to_string(),
        capabilities: vec![
            "spiffe-svid-issuance",
            "jwt-identity-tokens",
            "rego-policy-generation",
            "cedar-policy-generation",
            "istio-authz-generation",
            "opa-policy-evaluation",
            "zero-trust-enforcement",
            "audit-logging",
            "tars-llm-routing",
        ],
        standards: vec![
            "SPIFFE/SPIRE",
            "NIST SP 800-207 (Zero Trust)",
            "OAuth2/OIDC",
            "OPA/Rego",
            "AWS Cedar",
            "Istio AuthorizationPolicy",
            "mTLS",
        ],
        timestamp: chrono::Utc::now().to_rfc3339(),
    })
}
