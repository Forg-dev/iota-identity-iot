//! # Identity Manager for Device Client
//!
//! Manages the device's identity lifecycle:
//! - Loading existing identity from storage
//! - Checking credential validity and expiration
//! - Providing credentials for TLS authentication
//! - Handling credential refresh

use anyhow::Result;
use chrono::{DateTime, Utc};
use ed25519_dalek::{SigningKey, Signer, Verifier, VerifyingKey};
use tracing::{debug, info};

use shared::{
    config::DeviceClientConfig,
    error::{IdentityError, IdentityResult},
    types::DeviceIdentity,
};

use crate::storage::SecureStorage;

/// Identity Manager for device client
/// 
/// Provides a high-level interface for managing the device's identity,
/// including loading from storage, signing challenges, and checking
/// credential validity.
pub struct IdentityManager {
    /// Secure storage
    storage: SecureStorage,
    
    /// Signing key (if loaded)
    signing_key: Option<SigningKey>,
    
    /// Device identity (if loaded)
    identity: Option<DeviceIdentity>,
    
    /// Credential JWT (if loaded)
    credential_jwt: Option<String>,
    
    /// Credential expiration time (parsed from JWT)
    credential_expires: Option<DateTime<Utc>>,
    
    /// Identity Service URL for refresh (used in future credential renewal)
    #[allow(dead_code)]
    identity_service_url: String,
}

impl IdentityManager {
    /// Create a new Identity Manager and load existing identity
    pub async fn new(config: &DeviceClientConfig) -> Result<Self> {
        let storage = SecureStorage::new(&config.storage).await?;
        
        let mut manager = Self {
            storage,
            signing_key: None,
            identity: None,
            credential_jwt: None,
            credential_expires: None,
            identity_service_url: config.identity_service_url.clone(),
        };
        
        // Try to load existing identity
        manager.load().await?;
        
        Ok(manager)
    }
    
    /// Load identity from storage
    async fn load(&mut self) -> Result<()> {
        // Load private key
        if let Some(key_hex) = self.storage.load_private_key().await? {
            let key_bytes = hex::decode(&key_hex)?;
            let key_array: [u8; 32] = key_bytes.try_into()
                .map_err(|_| anyhow::anyhow!("Invalid private key length"))?;
            self.signing_key = Some(SigningKey::from_bytes(&key_array));
            debug!("Loaded private key from storage");
        }
        
        // Load identity
        if let Some(identity) = self.storage.load_identity().await? {
            info!(did = %identity.did, "Loaded device identity from storage");
            self.identity = Some(identity);
        }
        
        // Load credential JWT
        if let Some(jwt) = self.storage.load_credential_jwt().await? {
            self.credential_expires = Self::parse_jwt_expiration(&jwt);
            self.credential_jwt = Some(jwt);
            debug!("Loaded credential JWT from storage");
        }
        
        Ok(())
    }
    
    /// Parse expiration time from JWT (without full validation)
    fn parse_jwt_expiration(jwt: &str) -> Option<DateTime<Utc>> {
        // JWT format: header.payload.signature
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return None;
        }
        
        // Decode payload (with URL-safe base64)
        let payload = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            parts[1]
        ).ok()?;
        
        // Parse as JSON
        let json: serde_json::Value = serde_json::from_slice(&payload).ok()?;
        
        // Look for exp claim (standard JWT) or vc.expirationDate (VC)
        if let Some(exp) = json.get("exp").and_then(|v| v.as_i64()) {
            return DateTime::from_timestamp(exp, 0);
        }
        
        if let Some(exp_str) = json.get("vc")
            .and_then(|vc| vc.get("expirationDate"))
            .and_then(|v| v.as_str()) 
        {
            return DateTime::parse_from_rfc3339(exp_str)
                .ok()
                .map(|dt| dt.with_timezone(&Utc));
        }
        
        None
    }
    
    /// Check if the device has a valid identity
    pub fn is_initialized(&self) -> bool {
        self.identity.is_some() && self.signing_key.is_some() && self.credential_jwt.is_some()
    }
    
    /// Check if the credential is expired
    pub fn is_credential_expired(&self) -> bool {
        if let Some(expires) = self.credential_expires {
            expires < Utc::now()
        } else {
            // If we can't determine expiration, assume not expired
            false
        }
    }
    
    /// Check if credential will expire soon (within given hours)
    pub fn credential_expires_soon(&self, hours: i64) -> bool {
        if let Some(expires) = self.credential_expires {
            expires < Utc::now() + chrono::Duration::hours(hours)
        } else {
            false
        }
    }
    
    /// Get the device's DID
    pub fn did(&self) -> Option<&str> {
        self.identity.as_ref().map(|i| i.did.as_str())
    }
    
    /// Get the device's identity
    pub fn identity(&self) -> Option<&DeviceIdentity> {
        self.identity.as_ref()
    }
    
    /// Get the credential JWT
    pub fn credential_jwt(&self) -> Option<&str> {
        self.credential_jwt.as_deref()
    }
    
    /// Get credential expiration time
    pub fn credential_expires(&self) -> Option<DateTime<Utc>> {
        self.credential_expires
    }
    
    /// Sign data with the device's private key
    pub fn sign(&self, data: &[u8]) -> IdentityResult<Vec<u8>> {
        let key = self.signing_key.as_ref()
            .ok_or_else(|| IdentityError::InvalidRequest("No signing key loaded".into()))?;
        
        let signature = key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }
    
    /// Sign a challenge and return hex-encoded signature
    pub fn sign_challenge(&self, challenge: &str) -> IdentityResult<String> {
        let signature = self.sign(challenge.as_bytes())?;
        Ok(hex::encode(signature))
    }
    
    /// Get the public key (hex encoded)
    pub fn public_key_hex(&self) -> Option<String> {
        self.signing_key.as_ref().map(|k| {
            hex::encode(k.verifying_key().as_bytes())
        })
    }
    
    /// Verify a signature from another device
    pub fn verify_signature(
        public_key_hex: &str,
        data: &[u8],
        signature_hex: &str,
    ) -> IdentityResult<bool> {
        let public_key_bytes = hex::decode(public_key_hex)
            .map_err(|e| IdentityError::InvalidPublicKey(e.to_string()))?;
        
        let public_key_array: [u8; 32] = public_key_bytes.try_into()
            .map_err(|_| IdentityError::InvalidPublicKey("Invalid key length".into()))?;
        
        let public_key = VerifyingKey::from_bytes(&public_key_array)
            .map_err(|e| IdentityError::InvalidPublicKey(e.to_string()))?;
        
        let signature_bytes = hex::decode(signature_hex)
            .map_err(|e| IdentityError::InvalidSignature(e.to_string()))?;
        
        let signature_array: [u8; 64] = signature_bytes.try_into()
            .map_err(|_| IdentityError::InvalidSignature("Invalid signature length".into()))?;
        
        let signature = ed25519_dalek::Signature::from_bytes(&signature_array);
        
        Ok(public_key.verify(data, &signature).is_ok())
    }
    
    /// Get identity info for display
    pub fn info(&self) -> IdentityInfo {
        IdentityInfo {
            initialized: self.is_initialized(),
            did: self.did().map(|s| s.to_string()),
            public_key: self.public_key_hex(),
            credential_expires: self.credential_expires,
            credential_expired: self.is_credential_expired(),
            device_type: self.identity.as_ref().map(|i| format!("{:?}", i.device_type)),
            capabilities: self.identity.as_ref()
                .map(|i| i.capabilities.clone())
                .unwrap_or_default(),
        }
    }
}

/// Summary information about the device identity
#[derive(Debug, Clone)]
pub struct IdentityInfo {
    pub initialized: bool,
    pub did: Option<String>,
    pub public_key: Option<String>,
    pub credential_expires: Option<DateTime<Utc>>,
    pub credential_expired: bool,
    pub device_type: Option<String>,
    pub capabilities: Vec<String>,
}

impl std::fmt::Display for IdentityInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.initialized {
            writeln!(f, "Device Identity:")?;
            writeln!(f, "  DID: {}", self.did.as_deref().unwrap_or("unknown"))?;
            writeln!(f, "  Public Key: {}...", &self.public_key.as_deref().unwrap_or("unknown")[..16])?;
            writeln!(f, "  Type: {}", self.device_type.as_deref().unwrap_or("unknown"))?;
            writeln!(f, "  Capabilities: {:?}", self.capabilities)?;
            if let Some(expires) = self.credential_expires {
                writeln!(f, "  Credential Expires: {}", expires)?;
                if self.credential_expired {
                    writeln!(f, "  Status: EXPIRED")?;
                } else {
                    writeln!(f, "  Status: Valid")?;
                }
            }
        } else {
            writeln!(f, "Device not initialized. Run 'device-client register' first.")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use chrono::Duration;

    // Helper to create a fake JWT with given expiration timestamp
    fn create_fake_jwt_with_exp(exp_timestamp: i64) -> String {
        let fake_payload = serde_json::json!({
            "exp": exp_timestamp
        });
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&fake_payload).unwrap());
        format!("eyJhbGciOiJFZERTQSJ9.{}.fake_signature", payload_b64)
    }

    // Helper to create a fake JWT with VC expiration date format
    fn create_fake_jwt_with_vc_expiration(expiration_date: &str) -> String {
        let fake_payload = serde_json::json!({
            "vc": {
                "expirationDate": expiration_date
            }
        });
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&fake_payload).unwrap());
        format!("eyJhbGciOiJFZERTQSJ9.{}.fake_signature", payload_b64)
    }

    #[test]
    fn test_jwt_expiration_parsing_exp_claim() {
        // Test standard JWT exp claim (Unix timestamp)
        let future_timestamp = (Utc::now() + Duration::days(365)).timestamp();
        let jwt = create_fake_jwt_with_exp(future_timestamp);
        
        let expires = IdentityManager::parse_jwt_expiration(&jwt);
        assert!(expires.is_some());
        
        let parsed = expires.unwrap();
        // Should be approximately the same (within a second)
        assert!((parsed.timestamp() - future_timestamp).abs() < 2);
    }

    #[test]
    fn test_jwt_expiration_parsing_vc_format() {
        // Test W3C VC expirationDate format (ISO 8601)
        let jwt = create_fake_jwt_with_vc_expiration("2030-01-01T00:00:00Z");
        
        let expires = IdentityManager::parse_jwt_expiration(&jwt);
        assert!(expires.is_some());
        
        let parsed = expires.unwrap();
        assert_eq!(parsed.year(), 2030);
        assert_eq!(parsed.month(), 1);
        assert_eq!(parsed.day(), 1);
    }

    #[test]
    fn test_jwt_expiration_parsing_invalid_jwt() {
        // Invalid JWT format
        assert!(IdentityManager::parse_jwt_expiration("not.a.valid.jwt").is_none());
        assert!(IdentityManager::parse_jwt_expiration("").is_none());
        assert!(IdentityManager::parse_jwt_expiration("onlyonepart").is_none());
        
        // Valid structure but invalid base64
        assert!(IdentityManager::parse_jwt_expiration("header.!!!invalid!!!.sig").is_none());
    }

    #[test]
    fn test_jwt_expiration_parsing_no_exp_claim() {
        // JWT without expiration
        let fake_payload = serde_json::json!({
            "sub": "did:iota:test",
            "iss": "did:iota:issuer"
        });
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&fake_payload).unwrap());
        let jwt = format!("eyJhbGciOiJFZERTQSJ9.{}.fake_signature", payload_b64);
        
        let expires = IdentityManager::parse_jwt_expiration(&jwt);
        assert!(expires.is_none());
    }

    #[test]
    fn test_signature_verification_valid() {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let public_key_hex = hex::encode(signing_key.verifying_key().as_bytes());
        
        let data = b"test message for signing";
        let signature = signing_key.sign(data);
        let signature_hex = hex::encode(signature.to_bytes());
        
        let valid = IdentityManager::verify_signature(&public_key_hex, data, &signature_hex).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_signature_verification_wrong_data() {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let public_key_hex = hex::encode(signing_key.verifying_key().as_bytes());
        
        let data = b"original message";
        let signature = signing_key.sign(data);
        let signature_hex = hex::encode(signature.to_bytes());
        
        // Verify with different data should return false
        let invalid = IdentityManager::verify_signature(&public_key_hex, b"tampered message", &signature_hex).unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_signature_verification_wrong_key() {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let different_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let wrong_public_key_hex = hex::encode(different_key.verifying_key().as_bytes());
        
        let data = b"test message";
        let signature = signing_key.sign(data);
        let signature_hex = hex::encode(signature.to_bytes());
        
        // Verify with wrong public key should return false
        let invalid = IdentityManager::verify_signature(&wrong_public_key_hex, data, &signature_hex).unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_signature_verification_invalid_inputs() {
        // Invalid public key hex
        let result = IdentityManager::verify_signature("not_hex", b"data", "abcd".repeat(32).as_str());
        assert!(result.is_err());
        
        // Invalid public key length
        let result = IdentityManager::verify_signature("abcd", b"data", "abcd".repeat(32).as_str());
        assert!(result.is_err());
        
        // Invalid signature hex
        let valid_key = hex::encode([0u8; 32]);
        let result = IdentityManager::verify_signature(&valid_key, b"data", "not_hex");
        assert!(result.is_err());
        
        // Invalid signature length
        let result = IdentityManager::verify_signature(&valid_key, b"data", "abcd");
        assert!(result.is_err());
    }

    #[test]
    fn test_identity_info_display_initialized() {
        let info = IdentityInfo {
            initialized: true,
            did: Some("did:iota:testnet:0x123456789abcdef".to_string()),
            public_key: Some("abcdef1234567890abcdef1234567890".to_string()),
            credential_expires: Some(Utc::now() + Duration::days(30)),
            credential_expired: false,
            device_type: Some("Sensor".to_string()),
            capabilities: vec!["temperature".to_string(), "humidity".to_string()],
        };
        
        let display = format!("{}", info);
        assert!(display.contains("Device Identity:"));
        assert!(display.contains("did:iota:testnet:0x123456789abcdef"));
        assert!(display.contains("Sensor"));
        assert!(display.contains("Valid"));
    }

    #[test]
    fn test_identity_info_display_expired() {
        let info = IdentityInfo {
            initialized: true,
            did: Some("did:iota:testnet:0x123".to_string()),
            public_key: Some("abcdef1234567890".to_string()),
            credential_expires: Some(Utc::now() - Duration::days(1)),
            credential_expired: true,
            device_type: Some("Gateway".to_string()),
            capabilities: vec![],
        };
        
        let display = format!("{}", info);
        assert!(display.contains("EXPIRED"));
    }

    #[test]
    fn test_identity_info_display_not_initialized() {
        let info = IdentityInfo {
            initialized: false,
            did: None,
            public_key: None,
            credential_expires: None,
            credential_expired: false,
            device_type: None,
            capabilities: vec![],
        };
        
        let display = format!("{}", info);
        assert!(display.contains("not initialized"));
        assert!(display.contains("register"));
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        // Generate a keypair
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let public_key_hex = hex::encode(signing_key.verifying_key().as_bytes());
        
        // Sign a challenge
        let challenge = "random_challenge_12345";
        let signature = signing_key.sign(challenge.as_bytes());
        let signature_hex = hex::encode(signature.to_bytes());
        
        // Verify the signature
        let valid = IdentityManager::verify_signature(
            &public_key_hex,
            challenge.as_bytes(),
            &signature_hex
        ).unwrap();
        
        assert!(valid);
    }
}