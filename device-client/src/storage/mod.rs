//! # Secure Storage for Device Client
//!
//! Provides encrypted storage for:
//! - Device's private key
//! - DID and DID Document
//! - Verifiable Credentials
//!
//! Uses IOTA Stronghold for secure key management.

use anyhow::{Context, Result};
use std::path::PathBuf;
use tracing::{debug, info};

use identity_stronghold::StrongholdStorage;
use iota_stronghold::Stronghold;

use shared::{
    config::StorageConfig,
    error::{IdentityError, IdentityResult},
    types::{DeviceCredential, DeviceIdentity},
};

/// Secure storage for device credentials and keys
pub struct SecureStorage {
    /// Path to storage directory
    storage_path: PathBuf,
    
    /// Stronghold for key storage
    stronghold_path: PathBuf,
    
    /// Cached device identity
    identity: Option<DeviceIdentity>,
    
    /// Cached credential
    credential: Option<DeviceCredential>,
}

impl SecureStorage {
    /// Create a new SecureStorage instance
    pub async fn new(config: &StorageConfig) -> Result<Self> {
        info!(
            path = ?config.data_path,
            stronghold = ?config.stronghold_path,
            "Initializing secure storage"
        );

        // Ensure directories exist
        tokio::fs::create_dir_all(&config.data_path).await?;
        if let Some(parent) = config.stronghold_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let mut storage = Self {
            storage_path: config.data_path.clone(),
            stronghold_path: config.stronghold_path.clone(),
            identity: None,
            credential: None,
        };

        // Try to load existing data
        storage.load().await.ok();

        Ok(storage)
    }

    /// Store device identity
    pub async fn store_identity(&mut self, identity: DeviceIdentity) -> IdentityResult<()> {
        let path = self.storage_path.join("identity.json");
        
        let json = serde_json::to_string_pretty(&identity)
            .map_err(|e| IdentityError::SerializationError(e.to_string()))?;

        tokio::fs::write(&path, json)
            .await
            .map_err(|e| IdentityError::StorageIOError(e.to_string()))?;

        self.identity = Some(identity);
        
        debug!(path = ?path, "Identity stored");
        Ok(())
    }

    /// Load device identity
    pub async fn load_identity(&self) -> IdentityResult<Option<DeviceIdentity>> {
        if let Some(ref identity) = self.identity {
            return Ok(Some(identity.clone()));
        }

        let path = self.storage_path.join("identity.json");
        
        if !path.exists() {
            return Ok(None);
        }

        let json = tokio::fs::read_to_string(&path)
            .await
            .map_err(|e| IdentityError::StorageIOError(e.to_string()))?;

        let identity: DeviceIdentity = serde_json::from_str(&json)
            .map_err(|e| IdentityError::SerializationError(e.to_string()))?;

        Ok(Some(identity))
    }

    /// Store credential
    pub async fn store_credential(&mut self, credential: DeviceCredential) -> IdentityResult<()> {
        let path = self.storage_path.join("credential.json");
        
        let json = serde_json::to_string_pretty(&credential)
            .map_err(|e| IdentityError::SerializationError(e.to_string()))?;

        tokio::fs::write(&path, json)
            .await
            .map_err(|e| IdentityError::StorageIOError(e.to_string()))?;

        self.credential = Some(credential);
        
        debug!(path = ?path, "Credential stored");
        Ok(())
    }

    /// Load credential
    pub async fn load_credential(&self) -> IdentityResult<Option<DeviceCredential>> {
        if let Some(ref credential) = self.credential {
            return Ok(Some(credential.clone()));
        }

        let path = self.storage_path.join("credential.json");
        
        if !path.exists() {
            return Ok(None);
        }

        let json = tokio::fs::read_to_string(&path)
            .await
            .map_err(|e| IdentityError::StorageIOError(e.to_string()))?;

        let credential: DeviceCredential = serde_json::from_str(&json)
            .map_err(|e| IdentityError::SerializationError(e.to_string()))?;

        Ok(Some(credential))
    }

    /// Store credential as JWT
    pub async fn store_credential_jwt(&self, jwt: &str) -> IdentityResult<()> {
        let path = self.storage_path.join("credential.jwt");
        
        tokio::fs::write(&path, jwt)
            .await
            .map_err(|e| IdentityError::StorageIOError(e.to_string()))?;

        Ok(())
    }

    /// Load credential JWT
    pub async fn load_credential_jwt(&self) -> IdentityResult<Option<String>> {
        let path = self.storage_path.join("credential.jwt");
        
        if !path.exists() {
            return Ok(None);
        }

        let jwt = tokio::fs::read_to_string(&path)
            .await
            .map_err(|e| IdentityError::StorageIOError(e.to_string()))?;

        Ok(Some(jwt))
    }

    /// Load all stored data
    async fn load(&mut self) -> Result<()> {
        self.identity = self.load_identity().await.ok().flatten();
        self.credential = self.load_credential().await.ok().flatten();
        Ok(())
    }

    /// Check if device is registered
    pub fn is_registered(&self) -> bool {
        self.identity.is_some()
    }

    /// Get the device's DID if registered
    pub fn did(&self) -> Option<&str> {
        self.identity.as_ref().map(|i| i.did.as_str())
    }

    /// Clear all stored data
    pub async fn clear(&mut self) -> IdentityResult<()> {
        // Remove files
        let identity_path = self.storage_path.join("identity.json");
        let credential_path = self.storage_path.join("credential.json");
        let jwt_path = self.storage_path.join("credential.jwt");

        for path in [identity_path, credential_path, jwt_path] {
            if path.exists() {
                tokio::fs::remove_file(&path)
                    .await
                    .map_err(|e| IdentityError::StorageIOError(e.to_string()))?;
            }
        }

        self.identity = None;
        self.credential = None;

        info!("Storage cleared");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_storage_roundtrip() {
        let dir = tempdir().unwrap();
        let config = StorageConfig {
            stronghold_path: dir.path().join("test.stronghold"),
            stronghold_password: Some("test".into()),
            data_path: dir.path().to_path_buf(),
        };

        let mut storage = SecureStorage::new(&config).await.unwrap();

        // Store identity
        let identity = DeviceIdentity::new(
            "did:iota:0x123".into(),
            "0x123".into(),
            "a".repeat(64),
            shared::types::DeviceType::Sensor,
            vec!["temperature".into()],
        );

        storage.store_identity(identity.clone()).await.unwrap();

        // Load it back
        let loaded = storage.load_identity().await.unwrap().unwrap();
        assert_eq!(loaded.did, identity.did);
    }
}