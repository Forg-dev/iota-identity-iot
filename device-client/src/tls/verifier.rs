//! # Credential Verifier
//!
//! Verifies Verifiable Credentials (JWT) for TLS authentication.
//! This module provides local verification without requiring the Identity Service
//! to be online (except for DID resolution which can be cached).

use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use shared::error::{IdentityError, IdentityResult};

use crate::resolver::DIDResolver;

/// Parsed JWT credential for verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedCredential {
    /// Credential ID (urn:uuid:...)
    pub id: String,
    
    /// Subject DID (the device being authenticated)
    pub subject_did: String,
    
    /// Issuer DID
    pub issuer_did: String,
    
    /// Device type
    pub device_type: Option<String>,
    
    /// Device capabilities
    pub capabilities: Vec<String>,
    
    /// Issuance date
    pub issuance_date: DateTime<Utc>,
    
    /// Expiration date
    pub expiration_date: DateTime<Utc>,
    
    /// Revocation index (if present)
    pub revocation_index: Option<u32>,
}

/// JWT Header
#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    #[allow(dead_code)]
    typ: Option<String>,
}

/// JWT Payload for Verifiable Credential
#[derive(Debug, Deserialize)]
struct JwtPayload {
    /// Standard JWT issuer
    iss: Option<String>,
    
    /// Standard JWT subject
    sub: Option<String>,
    
    /// Standard JWT expiration (Unix timestamp)
    exp: Option<i64>,
    
    /// Standard JWT issued at
    iat: Option<i64>,
    
    /// Verifiable Credential content
    vc: Option<VcContent>,
}

/// Verifiable Credential content inside JWT
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VcContent {
    /// Credential ID
    id: Option<String>,
    
    /// Credential types
    #[serde(rename = "type")]
    #[allow(dead_code)]
    types: Option<Vec<String>>,
    
    /// Issuer
    issuer: Option<String>,
    
    /// Issuance date (ISO 8601)
    issuance_date: Option<String>,
    
    /// Expiration date (ISO 8601)
    expiration_date: Option<String>,
    
    /// Credential subject
    credential_subject: Option<CredentialSubject>,
    
    /// Credential status for revocation
    credential_status: Option<CredentialStatus>,
}

/// Credential subject
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialSubject {
    /// Subject DID
    id: Option<String>,
    
    /// Device type
    device_type: Option<String>,
    
    /// Capabilities
    capabilities: Option<Vec<String>>,
}

/// Credential status for revocation
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialStatus {
    /// Status type (should be "RevocationBitmap2022")
    #[serde(rename = "type")]
    #[allow(dead_code)]
    status_type: String,
    
    /// Revocation bitmap index
    revocation_bitmap_index: Option<String>,
}

/// Credential Verifier for TLS authentication
pub struct CredentialVerifier {
    /// DID Resolver for fetching issuer public keys
    resolver: std::sync::Arc<DIDResolver>,
    
    /// Identity Service URL for revocation checks
    identity_service_url: String,
    
    /// HTTP client for revocation checks
    http_client: reqwest::Client,
    
    /// Whether to check revocation status
    check_revocation: bool,
}

impl CredentialVerifier {
    /// Create a new credential verifier
    pub fn new(
        resolver: std::sync::Arc<DIDResolver>,
        identity_service_url: String,
        check_revocation: bool,
    ) -> Self {
        Self {
            resolver,
            identity_service_url,
            http_client: reqwest::Client::new(),
            check_revocation,
        }
    }
    
    /// Parse a JWT credential without verification
    pub fn parse_credential(jwt: &str) -> IdentityResult<ParsedCredential> {
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(IdentityError::InvalidCredential(
                "Invalid JWT format: expected 3 parts".into()
            ));
        }
        
        // Decode payload (second part)
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| IdentityError::InvalidCredential(
                format!("Invalid JWT payload encoding: {}", e)
            ))?;
        
        let payload: JwtPayload = serde_json::from_slice(&payload_bytes)
            .map_err(|e| IdentityError::InvalidCredential(
                format!("Invalid JWT payload: {}", e)
            ))?;
        
        // Extract credential info
        let vc = payload.vc.ok_or_else(|| IdentityError::InvalidCredential(
            "Missing vc claim in JWT".into()
        ))?;
        
        let subject = vc.credential_subject.ok_or_else(|| IdentityError::InvalidCredential(
            "Missing credentialSubject".into()
        ))?;
        
        // Parse dates
        let expiration_date = if let Some(exp) = payload.exp {
            DateTime::from_timestamp(exp, 0)
                .ok_or_else(|| IdentityError::InvalidCredential("Invalid exp timestamp".into()))?
        } else if let Some(exp_str) = &vc.expiration_date {
            DateTime::parse_from_rfc3339(exp_str)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| IdentityError::InvalidCredential(
                    format!("Invalid expirationDate: {}", e)
                ))?
        } else {
            return Err(IdentityError::InvalidCredential("Missing expiration".into()));
        };
        
        let issuance_date = if let Some(iat) = payload.iat {
            DateTime::from_timestamp(iat, 0)
                .ok_or_else(|| IdentityError::InvalidCredential("Invalid iat timestamp".into()))?
        } else if let Some(iss_str) = &vc.issuance_date {
            DateTime::parse_from_rfc3339(iss_str)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| IdentityError::InvalidCredential(
                    format!("Invalid issuanceDate: {}", e)
                ))?
        } else {
            Utc::now() // Default to now if not specified
        };
        
        // Extract revocation index
        let revocation_index = vc.credential_status
            .and_then(|cs| cs.revocation_bitmap_index)
            .and_then(|idx| idx.parse().ok());
        
        Ok(ParsedCredential {
            id: vc.id.unwrap_or_else(|| "unknown".into()),
            subject_did: subject.id.or(payload.sub).unwrap_or_default(),
            issuer_did: vc.issuer.or(payload.iss).unwrap_or_default(),
            device_type: subject.device_type,
            capabilities: subject.capabilities.unwrap_or_default(),
            issuance_date,
            expiration_date,
            revocation_index,
        })
    }
    
    /// Verify a JWT credential completely
    /// 
    /// This performs:
    /// 1. JWT structure validation
    /// 2. Signature verification using issuer's public key from blockchain
    /// 3. Expiration check
    /// 4. Subject DID matching
    /// 5. Revocation status check (if enabled)
    pub async fn verify_credential(
        &self,
        jwt: &str,
        expected_subject_did: &str,
    ) -> IdentityResult<ParsedCredential> {
        debug!("Verifying credential for subject: {}", expected_subject_did);
        
        // Parse the credential
        let credential = Self::parse_credential(jwt)?;
        
        // Check subject DID matches
        if credential.subject_did != expected_subject_did {
            return Err(IdentityError::DIDAuthenticationError(
                format!(
                    "Subject DID mismatch: expected {}, got {}",
                    expected_subject_did, credential.subject_did
                )
            ));
        }
        
        // Check expiration
        if credential.expiration_date < Utc::now() {
            return Err(IdentityError::CredentialExpired {
                expiration: credential.expiration_date.to_rfc3339(),
            });
        }
        
        // Verify signature
        self.verify_signature(jwt, &credential.issuer_did).await?;
        
        // Check revocation (if enabled)
        if self.check_revocation {
            if let Some(index) = credential.revocation_index {
                self.check_revocation_status(index).await?;
            }
        }
        
        debug!(
            credential_id = %credential.id,
            subject = %credential.subject_did,
            "Credential verified successfully"
        );
        
        Ok(credential)
    }
    
    /// Verify the JWT signature using the issuer's public key
    async fn verify_signature(&self, jwt: &str, issuer_did: &str) -> IdentityResult<()> {
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(IdentityError::InvalidCredential("Invalid JWT format".into()));
        }
        
        // Decode header to check algorithm
        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|e| IdentityError::InvalidCredential(
                format!("Invalid JWT header: {}", e)
            ))?;
        
        let header: JwtHeader = serde_json::from_slice(&header_bytes)
            .map_err(|e| IdentityError::InvalidCredential(
                format!("Invalid JWT header: {}", e)
            ))?;
        
        if header.alg != "EdDSA" {
            return Err(IdentityError::InvalidCredential(
                format!("Unsupported algorithm: {}. Expected EdDSA", header.alg)
            ));
        }
        
        // Decode signature
        let signature_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|e| IdentityError::InvalidSignature(
                format!("Invalid signature encoding: {}", e)
            ))?;
        
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|e| IdentityError::InvalidSignature(
                format!("Invalid signature format: {}", e)
            ))?;
        
        // Get issuer's public key from DID Document
        let public_key = self.get_issuer_public_key(issuer_did).await?;
        
        // The signed message is "header.payload"
        let signed_message = format!("{}.{}", parts[0], parts[1]);
        
        // Verify signature
        public_key.verify(signed_message.as_bytes(), &signature)
            .map_err(|e| IdentityError::InvalidSignature(
                format!("Signature verification failed: {}", e)
            ))?;
        
        debug!(issuer = %issuer_did, "Signature verified");
        Ok(())
    }
    
    /// Get the issuer's public key from their DID Document
    async fn get_issuer_public_key(&self, issuer_did: &str) -> IdentityResult<VerifyingKey> {
        // Resolve the DID document
        let did_document = self.resolver.resolve(issuer_did).await?;
        
        // Check if there are verification methods
        if did_document.verification_methods.is_empty() {
            return Err(IdentityError::DIDResolutionError {
                did: issuer_did.to_string(),
                reason: "No verificationMethod found".into(),
            });
        }
        
        // Try to find an Ed25519 key from verification methods
        for method in &did_document.verification_methods {
            // Try publicKeyMultibase (primary format for IOTA Identity)
            if let Some(public_key) = self.decode_multibase_key(&method.public_key_multibase) {
                return Ok(public_key);
            }
        }
        
        Err(IdentityError::DIDResolutionError {
            did: issuer_did.to_string(),
            reason: "No usable Ed25519 public key found".into(),
        })
    }
    
    /// Decode a multibase-encoded public key
    fn decode_multibase_key(&self, multibase: &str) -> Option<VerifyingKey> {
        // Multibase format: prefix + base-encoded data
        // 'z' prefix = base58btc
        if !multibase.starts_with('z') {
            warn!("Unsupported multibase prefix: {}", multibase.chars().next().unwrap_or('?'));
            return None;
        }
        
        // Decode base58
        let decoded = bs58::decode(&multibase[1..]).into_vec().ok()?;
        
        // The first bytes might be a multicodec prefix
        // Ed25519 public key multicodec: 0xed01
        let key_bytes = if decoded.len() == 34 && decoded[0] == 0xed && decoded[1] == 0x01 {
            &decoded[2..]
        } else if decoded.len() == 32 {
            &decoded[..]
        } else {
            warn!("Unexpected key length: {} bytes", decoded.len());
            return None;
        };
        
        let key_array: [u8; 32] = key_bytes.try_into().ok()?;
        VerifyingKey::from_bytes(&key_array).ok()
    }
    
    /// Check if a credential is revoked
    async fn check_revocation_status(&self, revocation_index: u32) -> IdentityResult<()> {
        let url = format!(
            "{}/api/v1/credential/status-onchain/{}",
            self.identity_service_url, revocation_index
        );
        
        let response = self.http_client
            .get(&url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| IdentityError::NetworkConnectionError {
                endpoint: url.clone(),
                reason: e.to_string(),
            })?;
        
        if !response.status().is_success() {
            // If we can't check revocation, log warning but continue
            // This allows offline operation with cached data
            warn!(
                "Could not check revocation status: HTTP {}",
                response.status()
            );
            return Ok(());
        }
        
        let status: serde_json::Value = response.json().await
            .map_err(|e| IdentityError::SerializationError(e.to_string()))?;
        
        if status.get("revoked").and_then(|v| v.as_bool()).unwrap_or(false) {
            return Err(IdentityError::CredentialRevoked {
                credential_id: format!("index:{}", revocation_index),
                reason: "Credential has been revoked".into(),
            });
        }
        
        debug!(index = revocation_index, "Revocation check passed");
        Ok(())
    }
}

/// Verify a challenge-response signature
/// 
/// This verifies that the peer actually possesses the private key
/// corresponding to their claimed DID.
pub fn verify_challenge_response(
    challenge: &str,
    response: &str,
    public_key_hex: &str,
) -> IdentityResult<bool> {
    let public_key_bytes = hex::decode(public_key_hex)
        .map_err(|e| IdentityError::InvalidSignature(
            format!("Invalid public key hex: {}", e)
        ))?;
    
    let public_key_array: [u8; 32] = public_key_bytes.try_into()
        .map_err(|_| IdentityError::InvalidSignature(
            "Public key must be 32 bytes".into()
        ))?;
    
    let public_key = VerifyingKey::from_bytes(&public_key_array)
        .map_err(|e| IdentityError::InvalidSignature(
            format!("Invalid public key: {}", e)
        ))?;
    
    let signature_bytes = hex::decode(response)
        .map_err(|e| IdentityError::InvalidSignature(
            format!("Invalid signature hex: {}", e)
        ))?;
    
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|e| IdentityError::InvalidSignature(
            format!("Invalid signature format: {}", e)
        ))?;
    
    match public_key.verify(challenge.as_bytes(), &signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, Signer};
    
    #[test]
    fn test_challenge_response_verification() {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let public_key_hex = hex::encode(signing_key.verifying_key().as_bytes());
        
        let challenge = "test_challenge_12345";
        let signature = signing_key.sign(challenge.as_bytes());
        let response = hex::encode(signature.to_bytes());
        
        let result = verify_challenge_response(challenge, &response, &public_key_hex);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
    
    #[test]
    fn test_challenge_response_wrong_signature() {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let different_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let public_key_hex = hex::encode(different_key.verifying_key().as_bytes());
        
        let challenge = "test_challenge_12345";
        let signature = signing_key.sign(challenge.as_bytes());
        let response = hex::encode(signature.to_bytes());
        
        let result = verify_challenge_response(challenge, &response, &public_key_hex);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
    
    #[test]
    fn test_parse_minimal_jwt() {
        // Create a minimal valid JWT payload
        let payload = serde_json::json!({
            "iss": "did:iota:testnet:issuer",
            "sub": "did:iota:testnet:subject",
            "exp": 4102444800i64, // 2100-01-01
            "iat": 1704067200i64, // 2024-01-01
            "vc": {
                "id": "urn:uuid:test-123",
                "type": ["VerifiableCredential"],
                "issuer": "did:iota:testnet:issuer",
                "credentialSubject": {
                    "id": "did:iota:testnet:subject",
                    "deviceType": "sensor",
                    "capabilities": ["temperature"]
                }
            }
        });
        
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"EdDSA","typ":"JWT"}"#);
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_string(&payload).unwrap());
        let fake_sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode([0u8; 64]);
        
        let jwt = format!("{}.{}.{}", header, payload_b64, fake_sig);
        
        let credential = CredentialVerifier::parse_credential(&jwt).unwrap();
        
        assert_eq!(credential.id, "urn:uuid:test-123");
        assert_eq!(credential.subject_did, "did:iota:testnet:subject");
        assert_eq!(credential.issuer_did, "did:iota:testnet:issuer");
        assert_eq!(credential.device_type, Some("sensor".to_string()));
        assert_eq!(credential.capabilities, vec!["temperature".to_string()]);
    }
}