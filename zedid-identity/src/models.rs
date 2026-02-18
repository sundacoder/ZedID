use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Represents the type of identity in ZedID
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum IdentityKind {
    /// Human user identity (OAuth2/OIDC)
    Human,
    /// Machine/workload identity (SPIFFE/SVID)
    Workload,
    /// AI Agent identity (for TARS-routed agents)
    AiAgent,
    /// Service account
    ServiceAccount,
}

/// Trust level assigned to an identity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// Untrusted — newly registered, not yet attested
    Untrusted = 0,
    /// Low trust — basic authentication only
    Low = 1,
    /// Medium trust — MFA verified
    Medium = 2,
    /// High trust — hardware-attested or SPIFFE-verified
    High = 3,
    /// Critical — privileged admin identity
    Critical = 4,
}

/// Core identity record in ZedID
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub id: Uuid,
    pub name: String,
    pub kind: IdentityKind,
    pub trust_level: TrustLevel,
    pub spiffe_id: Option<String>,
    pub email: Option<String>,
    pub namespace: String,
    pub labels: std::collections::HashMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub is_active: bool,
    pub svid_expiry: Option<DateTime<Utc>>,
}

impl Identity {
    pub fn new_workload(name: &str, namespace: &str, trust_domain: &str) -> Self {
        let id = Uuid::new_v4();
        let spiffe_id = format!("spiffe://{}/ns/{}/sa/{}", trust_domain, namespace, name);
        Self {
            id,
            name: name.to_string(),
            kind: IdentityKind::Workload,
            trust_level: TrustLevel::High,
            spiffe_id: Some(spiffe_id),
            email: None,
            namespace: namespace.to_string(),
            labels: std::collections::HashMap::new(),
            created_at: Utc::now(),
            last_seen: Utc::now(),
            is_active: true,
            svid_expiry: Some(Utc::now() + chrono::Duration::hours(1)),
        }
    }

    pub fn new_human(name: &str, email: &str, namespace: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.to_string(),
            kind: IdentityKind::Human,
            trust_level: TrustLevel::Medium,
            spiffe_id: None,
            email: Some(email.to_string()),
            namespace: namespace.to_string(),
            labels: std::collections::HashMap::new(),
            created_at: Utc::now(),
            last_seen: Utc::now(),
            is_active: true,
            svid_expiry: None,
        }
    }

    pub fn new_ai_agent(name: &str, namespace: &str, trust_domain: &str) -> Self {
        let id = Uuid::new_v4();
        let spiffe_id = format!("spiffe://{}/ns/{}/agent/{}", trust_domain, namespace, name);
        Self {
            id,
            name: name.to_string(),
            kind: IdentityKind::AiAgent,
            trust_level: TrustLevel::Medium,
            spiffe_id: Some(spiffe_id),
            email: None,
            namespace: namespace.to_string(),
            labels: std::collections::HashMap::new(),
            created_at: Utc::now(),
            last_seen: Utc::now(),
            is_active: true,
            svid_expiry: Some(Utc::now() + chrono::Duration::hours(4)),
        }
    }

    pub fn is_svid_valid(&self) -> bool {
        match &self.svid_expiry {
            Some(expiry) => *expiry > Utc::now(),
            None => true,
        }
    }

    pub fn svid_ttl_seconds(&self) -> Option<i64> {
        self.svid_expiry
            .map(|exp| (exp - Utc::now()).num_seconds().max(0))
    }
}

/// Represents a SPIFFE Verifiable Identity Document (SVID)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Svid {
    pub spiffe_id: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub bundle_pem: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub serial_number: String,
}

impl Svid {
    pub fn is_valid(&self) -> bool {
        Utc::now() < self.expires_at
    }

    pub fn ttl_seconds(&self) -> i64 {
        (self.expires_at - Utc::now()).num_seconds().max(0)
    }
}

/// Audit event for identity operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityAuditEvent {
    pub id: Uuid,
    pub identity_id: Uuid,
    pub action: String,
    pub actor: String,
    pub resource: String,
    pub decision: AuditDecision,
    pub reason: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuditDecision {
    Allow,
    Deny,
    Error,
}

impl IdentityAuditEvent {
    pub fn new(
        identity_id: Uuid,
        action: &str,
        actor: &str,
        resource: &str,
        decision: AuditDecision,
        reason: Option<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            identity_id,
            action: action.to_string(),
            actor: actor.to_string(),
            resource: resource.to_string(),
            decision,
            reason,
            timestamp: Utc::now(),
            metadata: serde_json::Value::Object(serde_json::Map::new()),
        }
    }
}

/// Request/response for identity creation
#[derive(Debug, Deserialize)]
pub struct CreateIdentityRequest {
    pub name: String,
    pub kind: IdentityKind,
    pub namespace: String,
    pub email: Option<String>,
    pub labels: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Serialize)]
pub struct CreateIdentityResponse {
    pub identity: Identity,
    pub svid: Option<Svid>,
    pub message: String,
}
