pub mod health;
pub mod identities;
pub mod policies;
pub mod audit;

use crate::state::AppState;
use axum::{routing::get, routing::post, Router};

pub fn router() -> Router<AppState> {
    Router::new()
        // Health & system
        .route("/health", get(health::health_check))
        .route("/system/info", get(health::system_info))
        // Identity management
        .route("/identities", get(identities::list_identities))
        .route("/identities", post(identities::create_identity))
        .route("/identities/:id", get(identities::get_identity))
        .route("/identities/:id/svid", get(identities::get_svid))
        .route("/identities/:id/token", post(identities::issue_token))
        // Policy management
        // IMPORTANT: static sub-paths (/generate, /evaluate) MUST be registered
        // before the dynamic /:id route, otherwise Axum will try to parse
        // "generate"/"evaluate" as UUIDs and return 422 Unprocessable Entity.
        .route("/policies", get(policies::list_policies))
        .route("/policies", post(policies::create_policy))
        .route("/policies/generate", post(policies::generate_policy))
        .route("/policies/evaluate", post(policies::evaluate_policy))
        .route("/policies/:id", get(policies::get_policy))
        .route("/policies/:id/activate", post(policies::activate_policy))
        .route("/policies/:id/disable", post(policies::disable_policy))
        // Audit log
        .route("/audit", get(audit::list_audit_events))
        .route("/audit/stats", get(audit::audit_stats))
}
