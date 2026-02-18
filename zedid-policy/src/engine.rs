use crate::error::PolicyError;
use crate::models::{
    AccessModel, Policy, PolicyDecisionRequest, PolicyDecisionResponse,
    PolicyKind, PolicyStatus, PolicyValidationResult,
};
use std::time::Instant;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// In-memory policy store (in production: PostgreSQL via sqlx)
pub struct PolicyEngine {
    policies: std::sync::Arc<tokio::sync::RwLock<Vec<Policy>>>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        let engine = Self {
            policies: std::sync::Arc::new(tokio::sync::RwLock::new(vec![])),
        };
        engine
    }

    pub async fn seed_demo_policies(&self) {
        let mut store = self.policies.write().await;

        // Demo policy 1: Checkout service can read inventory
        let mut p1 = Policy::new(
            "checkout-reads-inventory",
            "Allow checkout service to read inventory data",
            PolicyKind::Rego,
            AccessModel::ZeroTrust,
            DEMO_REGO_POLICY_1,
            "production",
            "zedid-system",
        );
        p1.status = PolicyStatus::Active;
        p1.subjects = vec!["spiffe://tetrate.io/ns/production/sa/checkout".to_string()];
        p1.resources = vec!["inventory-service".to_string()];
        p1.actions = vec!["GET".to_string(), "LIST".to_string()];
        p1.explanation = "The checkout service is permitted to read inventory data to display product availability. Write operations are explicitly denied.".to_string();
        p1.validation_passed = true;
        p1.tags = vec!["production".to_string(), "e-commerce".to_string()];

        // Demo policy 2: TARS AI agent routing policy
        let mut p2 = Policy::new(
            "tars-agent-llm-routing",
            "TARS AI agent routing policy — controls which LLMs agents can access",
            PolicyKind::Rego,
            AccessModel::Abac,
            DEMO_REGO_POLICY_2,
            "ai-platform",
            "zedid-system",
        );
        p2.status = PolicyStatus::Active;
        p2.subjects = vec!["spiffe://tetrate.io/ns/ai-platform/agent/*".to_string()];
        p2.resources = vec!["tars-router".to_string()];
        p2.actions = vec!["route".to_string()];
        p2.explanation = "AI agents with trust_level >= 2 may route requests through TARS. Budget limits are enforced per agent per day.".to_string();
        p2.ai_generated = true;
        p2.ai_model_used = Some("gemini-2.0-flash".to_string());
        p2.validation_passed = true;
        p2.tags = vec!["ai-governance".to_string(), "tars".to_string()];

        // Demo policy 3: Admin access policy
        let mut p3 = Policy::new(
            "admin-full-access",
            "Platform administrators have full access to ZedID management APIs",
            PolicyKind::Rego,
            AccessModel::Rbac,
            DEMO_REGO_POLICY_3,
            "system",
            "zedid-system",
        );
        p3.status = PolicyStatus::Active;
        p3.subjects = vec!["role:platform-admin".to_string()];
        p3.resources = vec!["zedid-api/*".to_string()];
        p3.actions = vec!["*".to_string()];
        p3.explanation = "Platform administrators can perform all operations on ZedID APIs. This policy requires trust_level=4 (Critical).".to_string();
        p3.validation_passed = true;
        p3.tags = vec!["admin".to_string(), "privileged".to_string()];

        store.push(p1);
        store.push(p2);
        store.push(p3);
        info!("Seeded {} demo policies", store.len());
    }

    pub async fn list_policies(&self, namespace: Option<&str>) -> Vec<Policy> {
        let store = self.policies.read().await;
        match namespace {
            Some(ns) => store.iter().filter(|p| p.namespace == ns).cloned().collect(),
            None => store.clone(),
        }
    }

    pub async fn get_policy(&self, id: Uuid) -> Option<Policy> {
        let store = self.policies.read().await;
        store.iter().find(|p| p.id == id).cloned()
    }

    pub async fn add_policy(&self, policy: Policy) -> Policy {
        let mut store = self.policies.write().await;
        store.push(policy.clone());
        info!("Policy added: {} ({})", policy.name, policy.id);
        policy
    }

    pub async fn update_policy_status(
        &self,
        id: Uuid,
        status: PolicyStatus,
    ) -> Result<Policy, PolicyError> {
        let mut store = self.policies.write().await;
        let policy = store
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or_else(|| PolicyError::NotFound(id.to_string()))?;
        policy.status = status;
        policy.updated_at = chrono::Utc::now();
        Ok(policy.clone())
    }

    /// Evaluate a policy decision — the core enforcement engine
    /// In production: calls OPA REST API or uses embedded regorus
    pub async fn evaluate(
        &self,
        req: &PolicyDecisionRequest,
    ) -> Result<PolicyDecisionResponse, PolicyError> {
        let start = Instant::now();
        debug!(
            "Evaluating: subject={} resource={} action={}",
            req.subject, req.resource, req.action
        );

        let store = self.policies.read().await;

        // Find applicable active policies
        let applicable: Vec<&Policy> = store
            .iter()
            .filter(|p| {
                p.status == PolicyStatus::Active
                    && (p.namespace == req.namespace || p.namespace == "system")
            })
            .collect();

        if applicable.is_empty() {
            warn!("No active policies found for namespace: {}", req.namespace);
            return Ok(PolicyDecisionResponse {
                allowed: false,
                reason: "No applicable policies found — deny by default".to_string(),
                policy_id: None,
                policy_name: None,
                evaluation_time_ms: start.elapsed().as_millis() as u64,
                decision_id: Uuid::new_v4(),
            });
        }

        // Simulate OPA evaluation logic
        // In production: POST to OPA /v1/data/zedid/allow
        for policy in &applicable {
            if let Some(result) = simulate_rego_evaluation(policy, req) {
                let elapsed = start.elapsed().as_millis() as u64;
                info!(
                    "Decision: {} | policy={} | {}ms",
                    if result { "ALLOW" } else { "DENY" },
                    policy.name,
                    elapsed
                );
                return Ok(PolicyDecisionResponse {
                    allowed: result,
                    reason: if result {
                        format!("Allowed by policy: {}", policy.name)
                    } else {
                        format!("Denied by policy: {}", policy.name)
                    },
                    policy_id: Some(policy.id),
                    policy_name: Some(policy.name.clone()),
                    evaluation_time_ms: elapsed,
                    decision_id: Uuid::new_v4(),
                });
            }
        }

        Ok(PolicyDecisionResponse {
            allowed: false,
            reason: "No matching policy rule — implicit deny".to_string(),
            policy_id: None,
            policy_name: None,
            evaluation_time_ms: start.elapsed().as_millis() as u64,
            decision_id: Uuid::new_v4(),
        })
    }

    /// Validate a policy document
    pub fn validate_policy(&self, policy: &Policy) -> PolicyValidationResult {
        let mut errors = vec![];
        let mut warnings = vec![];

        if policy.content.is_empty() {
            errors.push("Policy content cannot be empty".to_string());
        }

        if policy.subjects.is_empty() {
            warnings.push("No subjects specified — policy may be overly broad".to_string());
        }

        if policy.resources.is_empty() {
            warnings.push("No resources specified — policy may be overly broad".to_string());
        }

        match policy.kind {
            PolicyKind::Rego => {
                if !policy.content.contains("package") {
                    errors.push("Rego policy must have a package declaration".to_string());
                }
                if !policy.content.contains("allow") && !policy.content.contains("deny") {
                    warnings.push(
                        "Rego policy should define 'allow' or 'deny' rules".to_string(),
                    );
                }
            }
            PolicyKind::Cedar => {
                if !policy.content.contains("permit") && !policy.content.contains("forbid") {
                    errors.push("Cedar policy must have permit or forbid rules".to_string());
                }
            }
            _ => {}
        }

        let coverage_score = if errors.is_empty() {
            if warnings.is_empty() { 1.0 } else { 0.8 }
        } else {
            0.0
        };

        PolicyValidationResult {
            passed: errors.is_empty(),
            errors,
            warnings,
            coverage_score,
        }
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Simulate Rego evaluation logic
/// In production: use regorus crate or OPA REST API
fn simulate_rego_evaluation(policy: &Policy, req: &PolicyDecisionRequest) -> Option<bool> {
    // Check if any subject matches
    let subject_matches = policy.subjects.is_empty()
        || policy.subjects.iter().any(|s| {
            s == &req.subject
                || s.ends_with("/*")
                    && req.subject.starts_with(s.trim_end_matches("/*"))
                || s.starts_with("role:")
        });

    // Check if any resource matches
    let resource_matches = policy.resources.is_empty()
        || policy.resources.iter().any(|r| {
            r == &req.resource
                || r.ends_with("/*")
                || r == "*"
        });

    // Check if action matches
    let action_matches = policy.actions.is_empty()
        || policy.actions.iter().any(|a| a == &req.action || a == "*");

    if subject_matches && resource_matches && action_matches {
        Some(true)
    } else {
        None
    }
}

// Demo Rego policies
const DEMO_REGO_POLICY_1: &str = r#"package zedid.production.inventory

import future.keywords.if
import future.keywords.in

default allow := false

# Allow checkout service to read inventory
allow if {
    input.subject == "spiffe://tetrate.io/ns/production/sa/checkout"
    input.action in {"GET", "LIST"}
    input.resource == "inventory-service"
    input.trust_level >= 3
}

# Deny all write operations from checkout
deny if {
    input.subject == "spiffe://tetrate.io/ns/production/sa/checkout"
    input.action in {"POST", "PUT", "DELETE", "PATCH"}
}
"#;

const DEMO_REGO_POLICY_2: &str = r#"package zedid.ai.tars_routing

import future.keywords.if
import future.keywords.in

default allow := false

# AI agents with sufficient trust may route through TARS
allow if {
    startswith(input.subject, "spiffe://tetrate.io/ns/ai-platform/agent/")
    input.action == "route"
    input.resource == "tars-router"
    input.trust_level >= 2
    not budget_exceeded
}

# Budget enforcement: max 10000 tokens per day per agent
budget_exceeded if {
    input.context.daily_tokens_used > 10000
}

# High-risk model access requires higher trust
deny if {
    input.context.target_model in {"gpt-4o", "claude-3-opus"}
    input.trust_level < 3
}
"#;

const DEMO_REGO_POLICY_3: &str = r#"package zedid.system.admin

import future.keywords.if
import future.keywords.in

default allow := false

# Platform admins have full access
allow if {
    "platform-admin" in input.roles
    input.trust_level >= 4
    valid_session
}

valid_session if {
    input.context.mfa_verified == true
    input.context.session_age_minutes < 60
}
"#;
