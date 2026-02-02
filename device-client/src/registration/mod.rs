//! # Device Registration
//!
//! Handles device registration with the Identity Service:
//! 1. Generate Ed25519 keypair
//! 2. Call Identity Service API
//! 3. Receive DID and Verifiable Credential
//! 4. Store locally in secure storage

use anyhow::Result;
use ed25519_dalek::{SigningKey, Signer};
use rand::rngs::OsRng;
use tracing::{debug, info, warn};

use shared::{
    config::DeviceClientConfig,
    error::{IdentityError, IdentityResult},
    types::{DeviceRegistrationRequest, DeviceRegistrationResponse, DeviceType},
};

use crate::storage::SecureStorage;

/// Device Registrar for registering with Identity Service
pub struct DeviceRegistrar {
    /// Identity Service URL
    identity_service_url: String,
    
    /// HTTP client
    http_client: reqwest::Client,
    
    /// Secure storage for credentials
    storage: SecureStorage,
    
    /// Cached signing key (loaded from storage or generated)
    signing_key: Option<SigningKey>,
}

impl DeviceRegistrar {
    /// Create a new DeviceRegistrar
    pub async fn new(config: &DeviceClientConfig) -> Result<Self> {
        let storage = SecureStorage::new(&config.storage).await?;
        
        // Try to load existing private key
        let signing_key = if let Some(key_hex) = storage.load_private_key().await? {
            let key_bytes = hex::decode(&key_hex)
                .map_err(|e| anyhow::anyhow!("Invalid private key hex: {}", e))?;
            let key_array: [u8; 32] = key_bytes.try_into()
                .map_err(|_| anyhow::anyhow!("Invalid private key length"))?;
            Some(SigningKey::from_bytes(&key_array))
        } else {
            None
        };

        Ok(Self {
            identity_service_url: config.identity_service_url.clone(),
            http_client: reqwest::Client::new(),
            storage,
            signing_key,
        })
    }

    /// Register this device with the Identity Service
    ///
    /// # Arguments
    /// * `device_type` - Type of this device
    /// * `capabilities` - Device capabilities
    ///
    /// # Returns
    /// Registration response with DID and credential
    pub async fn register(
        &mut self,
        device_type: DeviceType,
        capabilities: Vec<String>,
    ) -> IdentityResult<DeviceRegistrationResponse> {
        info!(
            device_type = ?device_type,
            capabilities = ?capabilities,
            "Starting device registration"
        );

        // Generate keypair (or use existing)
        let signing_key = if let Some(ref key) = self.signing_key {
            warn!("Using existing keypair for registration");
            key.clone()
        } else {
            let key = SigningKey::generate(&mut OsRng);
            info!("Generated new Ed25519 keypair");
            key
        };
        
        let public_key = signing_key.verifying_key();
        let public_key_hex = hex::encode(public_key.as_bytes());
        let private_key_hex = hex::encode(signing_key.to_bytes());

        debug!(public_key = %public_key_hex, "Using keypair for registration");

        // Build request
        let request = DeviceRegistrationRequest {
            public_key: public_key_hex.clone(),
            device_type,
            capabilities: capabilities.clone(),
            manufacturer: None,
            model: None,
        };

        // Call Identity Service
        let url = format!("{}/api/v1/device/register", self.identity_service_url);
        
        let response = self.http_client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| IdentityError::RegistrationError(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(IdentityError::RegistrationError(
                format!("Registration failed with {}: {}", status, body)
            ));
        }

        let registration: DeviceRegistrationResponse = response
            .json()
            .await
            .map_err(|e| IdentityError::SerializationError(e.to_string()))?;

        info!(
            did = %registration.did,
            object_id = %registration.object_id,
            "Device registered successfully"
        );

        // Store private key FIRST (most important)
        self.storage.store_private_key(&private_key_hex).await?;
        self.signing_key = Some(signing_key);

        // Store identity
        let identity = shared::types::DeviceIdentity::new(
            registration.did.clone(),
            registration.object_id.clone(),
            public_key_hex,
            device_type,
            capabilities,
        );

        self.storage.store_identity(identity).await?;
        self.storage.store_credential_jwt(&registration.credential_jwt).await?;

        Ok(registration)
    }

    /// Check if device is already registered
    pub fn is_registered(&self) -> bool {
        self.storage.is_registered()
    }

    /// Get the device's DID if registered
    pub fn did(&self) -> Option<&str> {
        self.storage.did()
    }

    /// Get stored credential JWT
    pub async fn credential_jwt(&self) -> IdentityResult<Option<String>> {
        self.storage.load_credential_jwt().await
    }

    /// Get the signing key (if available)
    pub fn signing_key(&self) -> Option<&SigningKey> {
        self.signing_key.as_ref()
    }

    /// Sign data with the device's private key
    pub fn sign(&self, data: &[u8]) -> IdentityResult<Vec<u8>> {
        let key = self.signing_key.as_ref()
            .ok_or_else(|| IdentityError::InvalidRequest("No signing key available".into()))?;
        
        let signature = key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }

    /// Re-register the device (revokes old identity)
    pub async fn re_register(
        &mut self,
        device_type: DeviceType,
        capabilities: Vec<String>,
    ) -> IdentityResult<DeviceRegistrationResponse> {
        // Clear existing data (including private key)
        self.storage.clear().await?;
        self.signing_key = None;
        
        // Register fresh
        self.register(device_type, capabilities).await
    }
    
    /// Get a reference to the storage
    pub fn storage(&self) -> &SecureStorage {
        &self.storage
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key();
        let public_key_hex = hex::encode(public_key.as_bytes());
        
        // Ed25519 public key is 32 bytes = 64 hex chars
        assert_eq!(public_key_hex.len(), 64);
    }

    #[test]
    fn test_private_key_hex_encoding() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let private_key_hex = hex::encode(signing_key.to_bytes());
        
        // Ed25519 private key is 32 bytes = 64 hex chars
        assert_eq!(private_key_hex.len(), 64);
        
        // Should be able to decode back
        let decoded = hex::decode(&private_key_hex).unwrap();
        assert_eq!(decoded.len(), 32);
        
        // Should be able to recreate the key
        let key_array: [u8; 32] = decoded.try_into().unwrap();
        let recovered_key = SigningKey::from_bytes(&key_array);
        
        // Verify it's the same key by comparing public keys
        assert_eq!(
            signing_key.verifying_key().as_bytes(),
            recovered_key.verifying_key().as_bytes()
        );
    }

    #[test]
    fn test_signing_and_verification() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let data = b"test message for device authentication";
        let signature = signing_key.sign(data);
        
        // Verify signature
        use ed25519_dalek::Verifier;
        let public_key = signing_key.verifying_key();
        assert!(public_key.verify(data, &signature).is_ok());
        
        // Signature should be 64 bytes
        assert_eq!(signature.to_bytes().len(), 64);
    }

    #[test]
    fn test_signature_fails_with_wrong_data() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let data = b"original message";
        let signature = signing_key.sign(data);
        
        use ed25519_dalek::Verifier;
        let public_key = signing_key.verifying_key();
        
        // Should fail with different data
        assert!(public_key.verify(b"different message", &signature).is_err());
    }

    #[test]
    fn test_signature_fails_with_wrong_key() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let different_key = SigningKey::generate(&mut OsRng);
        
        let data = b"test message";
        let signature = signing_key.sign(data);
        
        use ed25519_dalek::Verifier;
        let wrong_public_key = different_key.verifying_key();
        
        // Should fail with wrong public key
        assert!(wrong_public_key.verify(data, &signature).is_err());
    }

    #[test]
    fn test_deterministic_signatures() {
        // Ed25519 signatures should be deterministic (same key + same data = same signature)
        let signing_key = SigningKey::generate(&mut OsRng);
        let data = b"test message";
        
        let sig1 = signing_key.sign(data);
        let sig2 = signing_key.sign(data);
        
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_different_messages_different_signatures() {
        let signing_key = SigningKey::generate(&mut OsRng);
        
        let sig1 = signing_key.sign(b"message one");
        let sig2 = signing_key.sign(b"message two");
        
        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }
}