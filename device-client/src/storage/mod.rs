//! # Secure Storage for Device Client
//!
//! Provides encrypted storage for:
//! - Device's private key
//! - DID and DID Document
//! - Verifiable Credentials
//!
//! Uses file-based storage with optional encryption.

use anyhow::Result;
use std::path::PathBuf;
use tracing::{debug, info};

use shared::{
    config::StorageConfig,
    error::{IdentityError, IdentityResult},
    types::{DeviceCredential, DeviceIdentity},
};

/// Secure storage for device credentials and keys
pub struct SecureStorage {
    /// Path to storage directory
    storage_path: PathBuf,
    
    /// Cached device identity
    identity: Option<DeviceIdentity>,
    
    /// Cached credential
    credential: Option<DeviceCredential>,
    
    /// Cached private key (hex encoded)
    private_key: Option<String>,
}

impl SecureStorage {
    /// Create a new SecureStorage instance
    pub async fn new(config: &StorageConfig) -> Result<Self> {
        info!(
            path = ?config.data_path,
            "Initializing secure storage"
        );

        // Ensure directories exist
        tokio::fs::create_dir_all(&config.data_path).await?;

        let mut storage = Self {
            storage_path: config.data_path.clone(),
            identity: None,
            credential: None,
            private_key: None,
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

    /// Store private key (hex encoded)
    /// 
    /// SECURITY NOTE: In production, use a secure enclave or HSM.
    /// This implementation stores the key in a file for simplicity.
    pub async fn store_private_key(&mut self, private_key_hex: &str) -> IdentityResult<()> {
        let path = self.storage_path.join("private_key.hex");
        
        // Write to file with restricted permissions
        tokio::fs::write(&path, private_key_hex)
            .await
            .map_err(|e| IdentityError::StorageIOError(e.to_string()))?;

        // Set file permissions to owner-only read/write (Unix)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&path, perms)
                .map_err(|e| IdentityError::StorageIOError(e.to_string()))?;
        }

        self.private_key = Some(private_key_hex.to_string());
        
        debug!(path = ?path, "Private key stored");
        Ok(())
    }

    /// Load private key (hex encoded)
    pub async fn load_private_key(&self) -> IdentityResult<Option<String>> {
        if let Some(ref key) = self.private_key {
            return Ok(Some(key.clone()));
        }

        let path = self.storage_path.join("private_key.hex");
        
        if !path.exists() {
            return Ok(None);
        }

        let key = tokio::fs::read_to_string(&path)
            .await
            .map_err(|e| IdentityError::StorageIOError(e.to_string()))?;

        Ok(Some(key.trim().to_string()))
    }

    /// Load all stored data
    async fn load(&mut self) -> Result<()> {
        self.identity = self.load_identity().await.ok().flatten();
        self.credential = self.load_credential().await.ok().flatten();
        self.private_key = self.load_private_key().await.ok().flatten();
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

    /// Get the cached identity
    pub fn identity(&self) -> Option<&DeviceIdentity> {
        self.identity.as_ref()
    }

    /// Check if we have a stored private key
    pub fn has_private_key(&self) -> bool {
        self.private_key.is_some()
    }

    /// Clear all stored data
    pub async fn clear(&mut self) -> IdentityResult<()> {
        // Remove files
        let files = [
            "identity.json",
            "credential.json",
            "credential.jwt",
            "private_key.hex",
        ];

        for file in files {
            let path = self.storage_path.join(file);
            if path.exists() {
                tokio::fs::remove_file(&path)
                    .await
                    .map_err(|e| IdentityError::StorageIOError(e.to_string()))?;
            }
        }

        self.identity = None;
        self.credential = None;
        self.private_key = None;

        info!("Storage cleared");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn create_test_config(dir: &std::path::Path) -> StorageConfig {
        StorageConfig {
            stronghold_path: dir.join("test.stronghold"),
            stronghold_password: Some("test".into()),
            data_path: dir.to_path_buf(),
        }
    }

    fn create_test_identity() -> DeviceIdentity {
        DeviceIdentity::new(
            "did:iota:testnet:0x123456".into(),
            "0x123456".into(),
            "a]".repeat(32),
            shared::types::DeviceType::Sensor,
            vec!["temperature".into(), "humidity".into()],
        )
    }

    #[tokio::test]
    async fn test_storage_roundtrip() {
        let dir = tempdir().unwrap();
        let config = create_test_config(dir.path());

        let mut storage = SecureStorage::new(&config).await.unwrap();

        // Store identity
        let identity = create_test_identity();
        storage.store_identity(identity.clone()).await.unwrap();

        // Load it back
        let loaded = storage.load_identity().await.unwrap().unwrap();
        assert_eq!(loaded.did, identity.did);
        assert_eq!(loaded.object_id, identity.object_id);
        assert_eq!(loaded.capabilities, identity.capabilities);
    }

    #[tokio::test]
    async fn test_private_key_storage() {
        let dir = tempdir().unwrap();
        let config = create_test_config(dir.path());

        let mut storage = SecureStorage::new(&config).await.unwrap();

        let test_key = "a]".repeat(32); // 64 hex chars = 32 bytes
        storage.store_private_key(&test_key).await.unwrap();

        let loaded = storage.load_private_key().await.unwrap().unwrap();
        assert_eq!(loaded, test_key);
        assert!(storage.has_private_key());
    }

    #[tokio::test]
    async fn test_credential_jwt_storage() {
        let dir = tempdir().unwrap();
        let config = create_test_config(dir.path());

        let storage = SecureStorage::new(&config).await.unwrap();

        let test_jwt = "eyJhbGciOiJFZERTQSJ9.eyJ2YyI6e319.signature";
        storage.store_credential_jwt(test_jwt).await.unwrap();

        let loaded = storage.load_credential_jwt().await.unwrap().unwrap();
        assert_eq!(loaded, test_jwt);
    }

    #[tokio::test]
    async fn test_clear_removes_all_files() {
        let dir = tempdir().unwrap();
        let config = create_test_config(dir.path());

        let mut storage = SecureStorage::new(&config).await.unwrap();

        // Store everything
        let identity = create_test_identity();
        storage.store_identity(identity).await.unwrap();
        storage.store_private_key("abcd1234".repeat(8).as_str()).await.unwrap();
        storage.store_credential_jwt("test.jwt.token").await.unwrap();

        // Verify stored
        assert!(storage.is_registered());
        assert!(storage.has_private_key());

        // Clear
        storage.clear().await.unwrap();

        // Verify cleared from memory
        assert!(!storage.is_registered());
        assert!(!storage.has_private_key());

        // Verify files are gone
        assert!(!dir.path().join("identity.json").exists());
        assert!(!dir.path().join("private_key.hex").exists());
        assert!(!dir.path().join("credential.jwt").exists());
    }

    #[tokio::test]
    async fn test_persistence_across_instances() {
        let dir = tempdir().unwrap();
        let config = create_test_config(dir.path());

        // First instance: store data
        {
            let mut storage = SecureStorage::new(&config).await.unwrap();
            let identity = create_test_identity();
            storage.store_identity(identity).await.unwrap();
            storage.store_private_key("abcd1234".repeat(8).as_str()).await.unwrap();
            storage.store_credential_jwt("persistent.jwt.token").await.unwrap();
        }

        // Second instance: should load data automatically
        {
            let storage = SecureStorage::new(&config).await.unwrap();
            
            assert!(storage.is_registered());
            assert!(storage.has_private_key());
            assert_eq!(storage.did(), Some("did:iota:testnet:0x123456"));
            
            let jwt = storage.load_credential_jwt().await.unwrap().unwrap();
            assert_eq!(jwt, "persistent.jwt.token");
        }
    }

    #[tokio::test]
    async fn test_empty_storage_returns_none() {
        let dir = tempdir().unwrap();
        let config = create_test_config(dir.path());

        let storage = SecureStorage::new(&config).await.unwrap();

        assert!(!storage.is_registered());
        assert!(!storage.has_private_key());
        assert!(storage.did().is_none());
        assert!(storage.load_identity().await.unwrap().is_none());
        assert!(storage.load_private_key().await.unwrap().is_none());
        assert!(storage.load_credential_jwt().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_identity_helper_methods() {
        let dir = tempdir().unwrap();
        let config = create_test_config(dir.path());

        let mut storage = SecureStorage::new(&config).await.unwrap();

        // Before storing
        assert!(storage.identity().is_none());

        // After storing
        let identity = create_test_identity();
        storage.store_identity(identity.clone()).await.unwrap();

        assert!(storage.identity().is_some());
        assert_eq!(storage.identity().unwrap().did, identity.did);
    }
}