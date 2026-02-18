use crate::state::AppState;
use axum::{extract::State, Json};
use serde::Serialize;
use zedid_identity::{AuditDecision, IdentityAuditEvent};

pub async fn list_audit_events(State(state): State<AppState>) -> Json<serde_json::Value> {
    let audit_log = state.audit_log.read().await;
    let events: Vec<&IdentityAuditEvent> = audit_log.iter().rev().take(100).collect();
    Json(serde_json::json!({
        "events": events,
        "total": audit_log.len(),
    }))
}

#[derive(Serialize)]
pub struct AuditStats {
    pub total_events: usize,
    pub allow_count: usize,
    pub deny_count: usize,
    pub error_count: usize,
    pub recent_actions: Vec<String>,
}

pub async fn audit_stats(State(state): State<AppState>) -> Json<AuditStats> {
    let audit_log = state.audit_log.read().await;
    let allow_count = audit_log
        .iter()
        .filter(|e| e.decision == AuditDecision::Allow)
        .count();
    let deny_count = audit_log
        .iter()
        .filter(|e| e.decision == AuditDecision::Deny)
        .count();
    let error_count = audit_log
        .iter()
        .filter(|e| e.decision == AuditDecision::Error)
        .count();

    let recent_actions: Vec<String> = audit_log
        .iter()
        .rev()
        .take(10)
        .map(|e| e.action.clone())
        .collect();

    Json(AuditStats {
        total_events: audit_log.len(),
        allow_count,
        deny_count,
        error_count,
        recent_actions,
    })
}
