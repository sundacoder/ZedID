use crate::error::IdentityError;
use crate::models::Svid;
use chrono::Utc;
use tracing::{debug, info};
use uuid::Uuid;

/// SPIFFE ID format: spiffe://<trust_domain>/<path>
pub struct SpiffeId {
    pub trust_domain: String,
    pub path: String,
}

impl SpiffeId {
    pub fn parse(uri: &str) -> Result<Self, IdentityError> {
        if !uri.starts_with("spiffe://") {
            return Err(IdentityError::InvalidSpiffeId(format!(
                "Must start with spiffe://: {}",
                uri
            )));
        }
        let without_scheme = &uri["spiffe://".len()..];
        let slash_pos = without_scheme
            .find('/')
            .ok_or_else(|| IdentityError::InvalidSpiffeId("Missing path component".to_string()))?;
        Ok(Self {
            trust_domain: without_scheme[..slash_pos].to_string(),
            path: without_scheme[slash_pos..].to_string(),
        })
    }

    pub fn to_uri(&self) -> String {
        format!("spiffe://{}{}", self.trust_domain, self.path)
    }
}

/// Simulated SPIRE workload API client
/// In production this connects to the SPIRE Agent via gRPC Unix socket
pub struct SpireClient {
    pub trust_domain: String,
    /// Unix socket path for production SPIRE Agent gRPC connection
    #[allow(dead_code)]
    pub agent_socket: String,
}

impl SpireClient {
    pub fn new(trust_domain: &str) -> Self {
        Self {
            trust_domain: trust_domain.to_string(),
            agent_socket: "/tmp/spire-agent/public/api.sock".to_string(),
        }
    }

    /// Issue a simulated SVID for a workload
    /// In production: calls SPIRE Agent Workload API via gRPC
    pub async fn issue_svid(
        &self,
        spiffe_id: &str,
        ttl_hours: i64,
    ) -> Result<Svid, IdentityError> {
        info!("Issuing SVID for: {}", spiffe_id);

        // Validate the SPIFFE ID
        SpiffeId::parse(spiffe_id)?;

        // In a real implementation, this would:
        // 1. Connect to SPIRE Agent via tonic gRPC
        // 2. Call FetchX509SVID RPC
        // 3. Return the actual X.509 certificate
        // For the prototype, we generate a realistic mock SVID
        let serial = Uuid::new_v4().to_string().replace('-', "");
        let now = Utc::now();
        let expires = now + chrono::Duration::hours(ttl_hours);

        let svid = Svid {
            spiffe_id: spiffe_id.to_string(),
            cert_pem: generate_mock_cert_pem(spiffe_id, &serial),
            key_pem: generate_mock_key_pem(),
            bundle_pem: generate_mock_bundle_pem(&self.trust_domain),
            issued_at: now,
            expires_at: expires,
            serial_number: serial,
        };

        debug!("SVID issued, TTL: {}h, expires: {}", ttl_hours, expires);
        Ok(svid)
    }

    /// Verify a SPIFFE ID belongs to the configured trust domain
    pub fn verify_trust_domain(&self, spiffe_id: &str) -> Result<bool, IdentityError> {
        let parsed = SpiffeId::parse(spiffe_id)?;
        Ok(parsed.trust_domain == self.trust_domain)
    }
}

fn generate_mock_cert_pem(spiffe_id: &str, serial: &str) -> String {
    format!(
        "-----BEGIN CERTIFICATE-----\n\
        MIICpDCCAYwCCQD{}==\n\
        Subject: URI:{}\n\
        Serial: {}\n\
        -----END CERTIFICATE-----",
        &serial[..16],
        spiffe_id,
        serial
    )
}

fn generate_mock_key_pem() -> String {
    let key_id = Uuid::new_v4().to_string().replace('-', "");
    format!(
        "-----BEGIN EC PRIVATE KEY-----\n\
        MHQCAQEEIBkjKL{}==\n\
        -----END EC PRIVATE KEY-----",
        &key_id[..16]
    )
}

fn generate_mock_bundle_pem(trust_domain: &str) -> String {
    format!(
        "-----BEGIN CERTIFICATE-----\n\
        # Trust bundle for: {}\n\
        MIICpDCCAYwCCQDRootCA==\n\
        -----END CERTIFICATE-----",
        trust_domain
    )
}
