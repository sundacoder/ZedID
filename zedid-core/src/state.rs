use crate::config::AppConfig;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use zedid_identity::{Identity, IdentityAuditEvent};
use zedid_identity::jwt::JwtService;
use zedid_identity::spiffe::SpireClient;
use zedid_policy::engine::PolicyEngine;
use zedid_policy::generator::PolicyGenerator;
use zedid_policy::tars::TarsClient;
use tracing::info;

/// Shared application state — injected into all axum handlers
#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub identities: Arc<RwLock<Vec<Identity>>>,
    pub audit_log: Arc<RwLock<Vec<IdentityAuditEvent>>>,
    pub policy_engine: Arc<PolicyEngine>,
    pub policy_generator: Arc<PolicyGenerator>,
    pub jwt_service: Arc<JwtService>,
    pub spire_client: Arc<SpireClient>,
}

impl AppState {
    pub async fn new(config: AppConfig) -> Result<Self> {
        // Initialize SPIRE client
        let spire_client = Arc::new(SpireClient::new(&config.trust_domain));

        // Initialize JWT service
        let jwt_service = Arc::new(JwtService::new(&config.jwt_secret, &config.jwt_issuer));

        // Initialize policy engine
        let policy_engine = Arc::new(PolicyEngine::new());

        // Initialize TARS client
        let tars_client = TarsClient::new(
            &config.tars_endpoint,
            config.tars_api_key.clone(),
        );

        // Initialize policy generator
        let policy_generator = Arc::new(PolicyGenerator::new(
            tars_client,
            Arc::clone(&policy_engine),
        ));

        // Seed demo data
        policy_engine.seed_demo_policies().await;
        let identities = Arc::new(RwLock::new(seed_demo_identities(&config.trust_domain)));

        info!("AppState initialized — ZedID ready");

        Ok(Self {
            config,
            identities,
            audit_log: Arc::new(RwLock::new(vec![])),
            policy_engine,
            policy_generator,
            jwt_service,
            spire_client,
        })
    }
}

fn seed_demo_identities(trust_domain: &str) -> Vec<Identity> {
    use zedid_identity::TrustLevel;

    vec![
        Identity::new_workload("checkout-service", "production", trust_domain),
        Identity::new_workload("payment-service", "production", trust_domain),
        Identity::new_workload("inventory-service", "production", trust_domain),
        Identity::new_workload("auth-service", "platform", trust_domain),
        Identity::new_ai_agent("tars-policy-agent", "ai-platform", trust_domain),
        Identity::new_ai_agent("anomaly-detector", "ai-platform", trust_domain),
        Identity::new_human("alice.chen", "alice.chen@tetrate.io", "platform"),
        Identity::new_human("bob.kumar", "bob.kumar@tetrate.io", "production"),
        {
            let mut admin = Identity::new_human("admin", "admin@tetrate.io", "system");
            admin.trust_level = TrustLevel::Critical;
            admin
        },
    ]
}
