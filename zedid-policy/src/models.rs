use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Policy type — what language/format the policy is in
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyKind {
    /// Open Policy Agent Rego policy
    Rego,
    /// AWS Cedar policy
    Cedar,
    /// Simple YAML-based RBAC policy
    RbacYaml,
    /// Istio AuthorizationPolicy
    IstioAuthz,
}

/// Policy lifecycle state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    /// AI-generated, awaiting human review
    Draft,
    /// Under review
    Review,
    /// Approved and active
    Active,
    /// Disabled but retained
    Disabled,
    /// Archived
    Archived,
}

/// Access control model
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AccessModel {
    Rbac,
    Abac,
    ReBAC,
    ZeroTrust,
}

/// A ZedID policy document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub kind: PolicyKind,
    pub access_model: AccessModel,
    pub status: PolicyStatus,
    /// The actual policy code (Rego, Cedar, YAML)
    pub content: String,
    /// Human-readable explanation of what this policy does
    pub explanation: String,
    /// Natural language intent that generated this policy
    pub natural_language_intent: Option<String>,
    /// Namespace this policy applies to
    pub namespace: String,
    /// Subjects this policy applies to (identity IDs or patterns)
    pub subjects: Vec<String>,
    /// Resources this policy governs
    pub resources: Vec<String>,
    /// Actions this policy controls
    pub actions: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    pub version: u32,
    pub tags: Vec<String>,
    pub ai_generated: bool,
    pub ai_model_used: Option<String>,
    pub validation_passed: bool,
}

impl Policy {
    pub fn new(
        name: &str,
        description: &str,
        kind: PolicyKind,
        access_model: AccessModel,
        content: &str,
        namespace: &str,
        created_by: &str,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.to_string(),
            description: description.to_string(),
            kind,
            access_model,
            status: PolicyStatus::Draft,
            content: content.to_string(),
            explanation: String::new(),
            natural_language_intent: None,
            namespace: namespace.to_string(),
            subjects: vec![],
            resources: vec![],
            actions: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: created_by.to_string(),
            version: 1,
            tags: vec![],
            ai_generated: false,
            ai_model_used: None,
            validation_passed: false,
        }
    }
}

/// Request to generate a policy from natural language
#[derive(Debug, Deserialize)]
pub struct GeneratePolicyRequest {
    /// Natural language description of the desired policy
    pub intent: String,
    /// Target policy format
    pub kind: PolicyKind,
    /// Access control model to use
    pub access_model: AccessModel,
    /// Namespace to scope the policy to
    pub namespace: String,
    /// Optional: specific subjects to include
    pub subjects: Option<Vec<String>>,
    /// Optional: specific resources to include
    pub resources: Option<Vec<String>>,
    /// Optional: specific actions to include
    pub actions: Option<Vec<String>>,
}

/// Result of policy generation
#[derive(Debug, Serialize)]
pub struct GeneratePolicyResponse {
    pub policy: Policy,
    pub validation_result: PolicyValidationResult,
    pub generation_time_ms: u64,
    pub model_used: String,
    pub tokens_used: Option<u32>,
}

/// Result of policy validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyValidationResult {
    pub passed: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub coverage_score: f32,
}

/// Policy decision request (for real-time enforcement)
#[derive(Debug, Deserialize)]
pub struct PolicyDecisionRequest {
    pub subject: String,
    pub resource: String,
    pub action: String,
    pub namespace: String,
    pub context: serde_json::Value,
}

/// Policy decision response
#[derive(Debug, Serialize)]
pub struct PolicyDecisionResponse {
    pub allowed: bool,
    pub reason: String,
    pub policy_id: Option<Uuid>,
    pub policy_name: Option<String>,
    pub evaluation_time_ms: u64,
    pub decision_id: Uuid,
}
