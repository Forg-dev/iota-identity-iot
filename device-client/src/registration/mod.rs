//! # Device Registration
//!
//! Handles device registration with the Identity Service:
//! 1. Generate Ed25519 keypair
//! 2. Call Identity Service API
//! 3. Receive DID and Verifiable Credential
//! 4. Store locally in secure storage

use anyhow::Result;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tracing::{debug, info};

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
}

impl DeviceRegistrar {
    /// Create a new DeviceRegistrar
    pub async fn new(config: &DeviceClientConfig) -> Result<Self> {
        let storage = SecureStorage::new(&config.storage).await?;

        Ok(Self {
            identity_service_url: config.identity_service_url.clone(),
            http_client: reqwest::Client::new(),
            storage,
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

        // Generate keypair
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key();
        let public_key_hex = hex::encode(public_key.as_bytes());

        debug!(public_key = %public_key_hex, "Generated keypair");

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

    /// Re-register the device (revokes old identity)
    pub async fn re_register(
        &mut self,
        device_type: DeviceType,
        capabilities: Vec<String>,
    ) -> IdentityResult<DeviceRegistrationResponse> {
        // Clear existing data
        self.storage.clear().await?;
        
        // Register fresh
        self.register(device_type, capabilities).await
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
        
        assert_eq!(public_key_hex.len(), 64);
    }
}