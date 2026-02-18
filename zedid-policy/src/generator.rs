use crate::error::PolicyError;
use crate::models::{
    AccessModel, GeneratePolicyRequest, GeneratePolicyResponse, Policy, PolicyKind, PolicyStatus,
};
use crate::tars::TarsClient;
use crate::engine::PolicyEngine;
use std::time::Instant;
use tracing::info;
use uuid::Uuid;

/// AI-powered policy generator using TARS for LLM routing
pub struct PolicyGenerator {
    tars: TarsClient,
    engine: std::sync::Arc<PolicyEngine>,
}

impl PolicyGenerator {
    pub fn new(tars: TarsClient, engine: std::sync::Arc<PolicyEngine>) -> Self {
        Self { tars, engine }
    }

    /// Generate a policy from natural language intent
    pub async fn generate(
        &self,
        req: &GeneratePolicyRequest,
        created_by: &str,
    ) -> Result<GeneratePolicyResponse, PolicyError> {
        let start = Instant::now();
        info!("Generating {} policy for intent: {}", format!("{:?}", req.kind), req.intent);

        // Build the prompt for the LLM
        let prompt = self.build_prompt(req);

        // Route through TARS to get the best LLM for policy generation
        let (generated_content, model_used, tokens_used) =
            self.tars.generate_policy(&prompt, &req.kind).await?;

        // Parse the generated content
        let (policy_code, explanation) = parse_llm_response(&generated_content, &req.kind);

        // Build the policy object
        let mut policy = Policy {
            id: Uuid::new_v4(),
            name: derive_policy_name(&req.intent),
            description: req.intent.clone(),
            kind: req.kind.clone(),
            access_model: req.access_model.clone(),
            status: PolicyStatus::Draft,
            content: policy_code,
            explanation,
            natural_language_intent: Some(req.intent.clone()),
            namespace: req.namespace.clone(),
            subjects: req.subjects.clone().unwrap_or_default(),
            resources: req.resources.clone().unwrap_or_default(),
            actions: req.actions.clone().unwrap_or_default(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            created_by: created_by.to_string(),
            version: 1,
            tags: vec!["ai-generated".to_string()],
            ai_generated: true,
            ai_model_used: Some(model_used.clone()),
            validation_passed: false,
        };

        // Validate the generated policy
        let validation = self.engine.validate_policy(&policy);
        policy.validation_passed = validation.passed;

        let elapsed = start.elapsed().as_millis() as u64;
        info!(
            "Policy generated in {}ms via {} | valid={}",
            elapsed, model_used, validation.passed
        );

        Ok(GeneratePolicyResponse {
            policy,
            validation_result: validation,
            generation_time_ms: elapsed,
            model_used,
            tokens_used,
        })
    }

    fn build_prompt(&self, req: &GeneratePolicyRequest) -> String {
        let format_name = match req.kind {
            PolicyKind::Rego => "Open Policy Agent (OPA) Rego",
            PolicyKind::Cedar => "AWS Cedar",
            PolicyKind::RbacYaml => "YAML RBAC",
            PolicyKind::IstioAuthz => "Istio AuthorizationPolicy",
        };

        let model_name = match req.access_model {
            AccessModel::Rbac => "Role-Based Access Control (RBAC)",
            AccessModel::Abac => "Attribute-Based Access Control (ABAC)",
            AccessModel::ReBAC => "Relationship-Based Access Control (ReBAC)",
            AccessModel::ZeroTrust => "Zero Trust (deny-by-default, least privilege)",
        };

        let subjects_hint = req
            .subjects
            .as_ref()
            .map(|s| format!("Subjects: {}", s.join(", ")))
            .unwrap_or_default();

        let resources_hint = req
            .resources
            .as_ref()
            .map(|r| format!("Resources: {}", r.join(", ")))
            .unwrap_or_default();

        let actions_hint = req
            .actions
            .as_ref()
            .map(|a| format!("Actions: {}", a.join(", ")))
            .unwrap_or_default();

        format!(
            r#"You are ZedID, an expert identity and access management policy generator.

Generate a {format_name} policy using the {model_name} model.

SECURITY INTENT:
{intent}

CONTEXT:
- Namespace: {namespace}
{subjects_hint}
{resources_hint}
{actions_hint}

REQUIREMENTS:
1. Follow zero-trust principles: deny by default
2. Use least-privilege access
3. Include comments explaining each rule
4. Make the policy production-ready
5. Include trust_level checks where appropriate

OUTPUT FORMAT:
Provide your response in this exact structure:
---POLICY---
[The complete policy code here]
---EXPLANATION---
[A clear, non-technical explanation of what this policy does and why]
---END---"#,
            format_name = format_name,
            model_name = model_name,
            intent = req.intent,
            namespace = req.namespace,
            subjects_hint = subjects_hint,
            resources_hint = resources_hint,
            actions_hint = actions_hint,
        )
    }
}

fn parse_llm_response(response: &str, _kind: &PolicyKind) -> (String, String) {
    // Parse structured LLM output
    if let (Some(policy_start), Some(policy_end)) = (
        response.find("---POLICY---"),
        response.find("---EXPLANATION---"),
    ) {
        let policy_code = response[policy_start + 12..policy_end].trim().to_string();
        let explanation = if let Some(end_pos) = response.find("---END---") {
            response[policy_end + 17..end_pos].trim().to_string()
        } else {
            response[policy_end + 17..].trim().to_string()
        };
        return (policy_code, explanation);
    }

    // Fallback: return raw response as policy code
    (response.to_string(), "AI-generated policy".to_string())
}

fn derive_policy_name(intent: &str) -> String {
    // Convert intent to a slug-like policy name
    let words: Vec<&str> = intent.split_whitespace().take(5).collect();
    let name = words.join("-").to_lowercase();
    let name = name
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-')
        .collect::<String>();
    format!("policy-{}", name)
}
