use crate::state::AppState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use uuid::Uuid;
use zedid_policy::models::{
    GeneratePolicyRequest, GeneratePolicyResponse, Policy, PolicyDecisionRequest,
    PolicyDecisionResponse, PolicyStatus,
};
use tracing::info;

#[derive(Deserialize)]
pub struct PolicyListQuery {
    pub namespace: Option<String>,
}

pub async fn list_policies(
    State(state): State<AppState>,
    Query(query): Query<PolicyListQuery>,
) -> Json<serde_json::Value> {
    let policies = state
        .policy_engine
        .list_policies(query.namespace.as_deref())
        .await;
    let total = policies.len();
    Json(serde_json::json!({
        "policies": policies,
        "total": total,
    }))
}

pub async fn get_policy(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Policy>, StatusCode> {
    state
        .policy_engine
        .get_policy(id)
        .await
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

pub async fn create_policy(
    State(state): State<AppState>,
    Json(mut policy): Json<Policy>,
) -> Json<Policy> {
    policy.id = Uuid::new_v4();
    policy.created_at = chrono::Utc::now();
    policy.updated_at = chrono::Utc::now();

    let validation = state.policy_engine.validate_policy(&policy);
    policy.validation_passed = validation.passed;

    state.policy_engine.add_policy(policy.clone()).await;
    Json(policy)
}

pub async fn generate_policy(
    State(state): State<AppState>,
    Json(req): Json<GeneratePolicyRequest>,
) -> Result<Json<GeneratePolicyResponse>, (StatusCode, Json<serde_json::Value>)> {
    info!("Policy generation request: {}", req.intent);

    let response = state
        .policy_generator
        .generate(&req, "zedid-api-user")
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
        })?;

    Ok(Json(response))
}

pub async fn evaluate_policy(
    State(state): State<AppState>,
    Json(req): Json<PolicyDecisionRequest>,
) -> Result<Json<PolicyDecisionResponse>, (StatusCode, Json<serde_json::Value>)> {
    let response = state
        .policy_engine
        .evaluate(&req)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
        })?;

    Ok(Json(response))
}

pub async fn activate_policy(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Policy>, (StatusCode, Json<serde_json::Value>)> {
    state
        .policy_engine
        .update_policy_status(id, PolicyStatus::Active)
        .await
        .map(Json)
        .map_err(|e| {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": e.to_string()})),
            )
        })
}

pub async fn disable_policy(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Policy>, (StatusCode, Json<serde_json::Value>)> {
    state
        .policy_engine
        .update_policy_status(id, PolicyStatus::Disabled)
        .await
        .map(Json)
        .map_err(|e| {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": e.to_string()})),
            )
        })
}
