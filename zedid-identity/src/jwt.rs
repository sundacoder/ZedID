use crate::error::IdentityError;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

/// JWT Claims for ZedID identity tokens
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ZedIdClaims {
    /// Subject (identity ID)
    pub sub: String,
    /// Issuer
    pub iss: String,
    /// Audience
    pub aud: Vec<String>,
    /// Expiry (Unix timestamp)
    pub exp: i64,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// JWT ID
    pub jti: String,
    /// Identity name
    pub name: String,
    /// Namespace
    pub namespace: String,
    /// Identity kind
    pub kind: String,
    /// Trust level (0-4)
    pub trust_level: u8,
    /// SPIFFE ID (if workload)
    pub spiffe_id: Option<String>,
}

pub struct JwtService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    issuer: String,
}

impl JwtService {
    pub fn new(secret: &str, issuer: &str) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            issuer: issuer.to_string(),
        }
    }

    pub fn issue_token(
        &self,
        subject: &str,
        name: &str,
        namespace: &str,
        kind: &str,
        trust_level: u8,
        spiffe_id: Option<String>,
        ttl_minutes: i64,
    ) -> Result<String, IdentityError> {
        let now = Utc::now();
        let exp = now + Duration::minutes(ttl_minutes);

        let claims = ZedIdClaims {
            sub: subject.to_string(),
            iss: self.issuer.clone(),
            aud: vec!["zedid-api".to_string()],
            exp: exp.timestamp(),
            iat: now.timestamp(),
            jti: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            namespace: namespace.to_string(),
            kind: kind.to_string(),
            trust_level,
            spiffe_id,
        };

        let header = Header::new(Algorithm::HS256);
        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| IdentityError::JwtValidationFailed(e.to_string()))
    }

    pub fn validate_token(&self, token: &str) -> Result<ZedIdClaims, IdentityError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&["zedid-api"]);
        validation.set_issuer(&[&self.issuer]);

        decode::<ZedIdClaims>(token, &self.decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|e| IdentityError::JwtValidationFailed(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_roundtrip() {
        let svc = JwtService::new("test-secret-key-zedid", "zedid.tetrate.io");
        let token = svc
            .issue_token(
                "identity-123",
                "checkout-service",
                "production",
                "workload",
                3,
                Some("spiffe://tetrate.io/ns/production/sa/checkout".to_string()),
                60,
            )
            .unwrap();

        let claims = svc.validate_token(&token).unwrap();
        assert_eq!(claims.sub, "identity-123");
        assert_eq!(claims.name, "checkout-service");
        assert_eq!(claims.trust_level, 3);
    }
}
