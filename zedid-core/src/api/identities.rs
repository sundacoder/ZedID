use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zedid_identity::{
    AuditDecision, CreateIdentityRequest, CreateIdentityResponse, Identity, IdentityAuditEvent,
    IdentityKind,
};
use tracing::{info, warn}; // warn used for SVID issuance failures

#[derive(Serialize)]
pub struct IdentityListResponse {
    pub identities: Vec<Identity>,
    pub total: usize,
    pub trust_domain: String,
}

pub async fn list_identities(State(state): State<AppState>) -> Json<IdentityListResponse> {
    let identities = state.identities.read().await;
    let total = identities.len();
    Json(IdentityListResponse {
        identities: identities.clone(),
        total,
        trust_domain: state.config.trust_domain.clone(),
    })
}

pub async fn get_identity(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Identity>, StatusCode> {
    let identities = state.identities.read().await;
    identities
        .iter()
        .find(|i| i.id == id)
        .cloned()
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

pub async fn create_identity(
    State(state): State<AppState>,
    Json(req): Json<CreateIdentityRequest>,
) -> Result<Json<CreateIdentityResponse>, StatusCode> {
    info!("Creating identity: {} ({:?})", req.name, req.kind);

    let identity = match req.kind {
        IdentityKind::Workload => {
            Identity::new_workload(&req.name, &req.namespace, &state.config.trust_domain)
        }
        IdentityKind::Human => {
            let email = req.email.unwrap_or_else(|| format!("{}@{}", req.name, state.config.trust_domain));
            Identity::new_human(&req.name, &email, &req.namespace)
        }
        IdentityKind::AiAgent => {
            Identity::new_ai_agent(&req.name, &req.namespace, &state.config.trust_domain)
        }
        IdentityKind::ServiceAccount => {
            Identity::new_workload(&req.name, &req.namespace, &state.config.trust_domain)
        }
    };

    // Issue SVID for workload identities
    let svid = if identity.spiffe_id.is_some() {
        match state
            .spire_client
            .issue_svid(identity.spiffe_id.as_ref().unwrap(), 1)
            .await
        {
            Ok(svid) => Some(svid),
            Err(e) => {
                warn!("SVID issuance failed: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Record audit event
    let audit = IdentityAuditEvent::new(
        identity.id,
        "identity.create",
        "zedid-api",
        &format!("identity/{}", identity.id),
        AuditDecision::Allow,
        Some(format!("Identity created: {} ({:?})", identity.name, identity.kind)),
    );

    let mut audit_log = state.audit_log.write().await;
    audit_log.push(audit);

    let mut identities = state.identities.write().await;
    identities.push(identity.clone());

    Ok(Json(CreateIdentityResponse {
        message: format!("Identity '{}' created successfully", identity.name),
        svid,
        identity,
    }))
}

#[derive(Serialize)]
pub struct SvidResponse {
    pub identity_id: Uuid,
    pub spiffe_id: String,
    pub svid: zedid_identity::Svid,
}

pub async fn get_svid(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<SvidResponse>, (StatusCode, Json<serde_json::Value>)> {
    let identities = state.identities.read().await;
    let identity = identities
        .iter()
        .find(|i| i.id == id)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Identity not found"})),
            )
        })?;

    let spiffe_id = identity.spiffe_id.as_ref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Identity does not have a SPIFFE ID (human identities use JWT tokens)"})),
        )
    })?;

    let svid = state
        .spire_client
        .issue_svid(spiffe_id, 1)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
        })?;

    Ok(Json(SvidResponse {
        identity_id: id,
        spiffe_id: spiffe_id.clone(),
        svid,
    }))
}

#[derive(Deserialize)]
pub struct IssueTokenRequest {
    pub ttl_minutes: Option<i64>,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub token: String,
    pub expires_in_seconds: i64,
    pub identity_id: Uuid,
    pub kind: String,
}

pub async fn issue_token(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<IssueTokenRequest>,
) -> Result<Json<TokenResponse>, (StatusCode, Json<serde_json::Value>)> {
    let identities = state.identities.read().await;
    let identity = identities
        .iter()
        .find(|i| i.id == id)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Identity not found"})),
            )
        })?;

    let ttl = req.ttl_minutes.unwrap_or(60);
    let trust_level = match identity.trust_level {
        zedid_identity::TrustLevel::Untrusted => 0,
        zedid_identity::TrustLevel::Low => 1,
        zedid_identity::TrustLevel::Medium => 2,
        zedid_identity::TrustLevel::High => 3,
        zedid_identity::TrustLevel::Critical => 4,
    };

    let token = state
        .jwt_service
        .issue_token(
            &identity.id.to_string(),
            &identity.name,
            &identity.namespace,
            &format!("{:?}", identity.kind).to_lowercase(),
            trust_level,
            identity.spiffe_id.clone(),
            ttl,
        )
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
        })?;

    Ok(Json(TokenResponse {
        token,
        expires_in_seconds: ttl * 60,
        identity_id: id,
        kind: format!("{:?}", identity.kind).to_lowercase(),
    }))
}
