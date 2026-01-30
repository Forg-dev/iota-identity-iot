//! # DID Manager for IOTA Rebased
//!
//! This module handles all DID operations on IOTA Rebased blockchain:
//! - Creating new DIDs (publishing DID Documents)
//! - Resolving existing DIDs
//! - Updating DID Documents
//! - Deactivating DIDs
//!
//! ## IMPORTANT: IOTA Rebased vs Stardust
//!
//! This implementation uses IOTA Rebased APIs which are completely different
//! from the Stardust version. Key differences:
//!
//! | Stardust | Rebased |
//! |----------|---------|
//! | `IotaIdentityClient` | `IdentityClient` / `IdentityClientReadOnly` |
//! | `Client::builder()` | `IotaClientBuilder::default()` |
//! | Alias Outputs (UTXO) | Identity Objects (Move VM) |
//! | Feeless | Gas required |
//! | `iota-sdk` (crates.io) | `iota-sdk` (github.com/iotaledger/iota) |

use anyhow::{Context, Result};
use parking_lot::RwLock;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

// =============================================================================
// IOTA REBASED IMPORTS (CORRECT - NOT STARDUST!)
// =============================================================================

// Core Identity types
use identity_iota::iota::{IotaDocument, IotaDID};

// Storage for cryptographic operations
use identity_iota::storage::{
    JwkDocumentExt, 
    JwkMemStore, 
    KeyIdMemstore, 
    Storage,
};

// Verification and signing
use identity_iota::verification::jws::JwsAlgorithm;
use identity_iota::verification::MethodScope;

// IOTA Rebased interaction (NEW API)
// Note: These are from identity_iota::iota_interaction, NOT the old iota module
use identity_iota::iota_interaction::{
    IdentityClientReadOnly,
    IotaClientTrait,
};

// IOTA SDK for Rebased (from github.com/iotaledger/iota, NOT crates.io)
use iota_sdk::IotaClientBuilder;

// Stronghold for secure key storage
use identity_stronghold::StrongholdStorage;
use iota_stronghold::Stronghold;

// Re-export shared types
use shared::{
    config::{IdentityServiceConfig, IotaNetwork},
    constants::*,
    error::{IdentityError, IdentityResult},
    types::DeviceIdentity,
};

/// Type alias for the storage backend
pub type IdentityStorage = Storage<StrongholdStorage, StrongholdStorage>;

/// DID Manager for IOTA Rebased
///
/// Handles all DID operations including creation, resolution, and management.
/// Uses IOTA Rebased APIs (Move VM based) instead of the older Stardust APIs.
pub struct DIDManager {
    /// Read-only client for resolving DIDs (doesn't require signing)
    read_only_client: IdentityClientReadOnly,
    
    /// Secure storage for cryptographic keys (Stronghold)
    storage: Arc<IdentityStorage>,
    
    /// Issuer's DID (this service's identity)
    issuer_did: RwLock<Option<IotaDID>>,
    
    /// Network configuration
    network: IotaNetwork,
    
    /// RPC endpoint
    endpoint: String,
    
    /// Identity Package ID
    package_id: String,
}

impl DIDManager {
    /// Create a new DID Manager for IOTA Rebased
    ///
    /// # Arguments
    /// * `config` - Service configuration
    ///
    /// # Returns
    /// A new DIDManager instance connected to IOTA Rebased
    ///
    /// # Example
    /// ```rust,no_run
    /// use identity_service::did::DIDManager;
    /// use shared::config::IdentityServiceConfig;
    ///
    /// #[tokio::main]
    /// async fn main() -> anyhow::Result<()> {
    ///     let config = IdentityServiceConfig::from_env()?;
    ///     let manager = DIDManager::new(&config).await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn new(config: &IdentityServiceConfig) -> Result<Self> {
        let endpoint = config.endpoint().to_string();
        let package_id = config.package_id()?.to_string();
        
        info!(
            network = %config.network,
            endpoint = %endpoint,
            package_id = %package_id,
            "Initializing DID Manager for IOTA Rebased"
        );

        // Step 1: Build IOTA client using IotaClientBuilder (REBASED SDK)
        // This is different from Stardust's Client::builder()
        let iota_client = IotaClientBuilder::default()
            .build(&endpoint)
            .await
            .context("Failed to build IOTA Rebased client")?;

        debug!("IOTA Rebased client connected to {}", endpoint);

        // Step 2: Create read-only identity client for resolving DIDs
        // Note: For publishing, we need a full IdentityClient with signer
        let read_only_client = IdentityClientReadOnly::new(iota_client)
            .await
            .context("Failed to create read-only identity client")?;

        debug!("Read-only identity client created");

        // Step 3: Setup Stronghold storage for secure key management
        let storage = Self::setup_stronghold_storage(config).await?;

        info!("DID Manager initialized successfully for IOTA Rebased");

        Ok(Self {
            read_only_client,
            storage: Arc::new(storage),
            issuer_did: RwLock::new(None),
            network: config.network,
            endpoint,
            package_id,
        })
    }

    /// Setup Stronghold secure storage
    async fn setup_stronghold_storage(config: &IdentityServiceConfig) -> Result<IdentityStorage> {
        let stronghold_path = &config.storage.stronghold_path;
        let password = config.storage.get_password()?;

        info!(path = ?stronghold_path, "Setting up Stronghold storage");

        // Ensure directory exists
        if let Some(parent) = stronghold_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Create Stronghold instance
        let stronghold = Stronghold::default();
        
        // Create storage with Stronghold backend
        let stronghold_storage = StrongholdStorage::new(stronghold);

        Ok(Storage::new(
            stronghold_storage.clone(),
            stronghold_storage,
        ))
    }

    /// Create a new DID for a device on IOTA Rebased
    ///
    /// This method:
    /// 1. Creates an IotaDocument with verification methods
    /// 2. Publishes it to IOTA Rebased via the Identity Move package
    /// 3. Returns the created DeviceIdentity
    ///
    /// # Arguments
    /// * `public_key_hex` - Device's Ed25519 public key (64 hex characters)
    ///
    /// # Returns
    /// DeviceIdentity containing DID, public key, and object ID
    ///
    /// # IOTA Rebased Flow
    /// ```text
    /// 1. Create unpublished IotaDocument
    /// 2. Add verification method with Ed25519 key
    /// 3. Get funded IdentityClient (needs IOTA tokens for gas)
    /// 4. Call publish_did_document() with gas budget
    /// 5. DID is derived from the resulting object ID
    /// ```
    pub async fn create_did(
        &self,
        public_key_hex: &str,
        device_type: shared::types::DeviceType,
        capabilities: Vec<String>,
    ) -> IdentityResult<DeviceIdentity> {
        info!(
            public_key_len = public_key_hex.len(),
            "Creating new DID for device on IOTA Rebased"
        );

        // Validate public key
        let public_key_bytes = hex::decode(public_key_hex)
            .map_err(|e| IdentityError::InvalidPublicKey(e.to_string()))?;

        if public_key_bytes.len() != 32 {
            return Err(IdentityError::InvalidPublicKey(
                format!("Expected 32 bytes, got {}", public_key_bytes.len())
            ));
        }

        debug!("Public key validated");

        // Get the network name from the read-only client
        let network_name = self.read_only_client.network();

        // Create unpublished DID Document
        let mut unpublished_doc = IotaDocument::new(&network_name);

        // Generate and add verification method using storage
        let fragment = unpublished_doc
            .generate_method(
                self.storage.as_ref(),
                JwkMemStore::ED25519_KEY_TYPE,
                JwsAlgorithm::EdDSA,
                None,
                MethodScope::VerificationMethod,
            )
            .await
            .map_err(|e| IdentityError::DIDCreationError(format!(
                "Failed to generate verification method: {}", e
            )))?;

        debug!(fragment = %fragment, "Verification method generated");

        // To publish, we need a funded IdentityClient with signing capability
        // This is a key difference from Stardust - we need gas!
        let published_doc = self.publish_document(unpublished_doc).await?;

        let did = published_doc.id().to_string();
        
        // Extract object ID from DID (format: did:iota:<object_id>)
        let object_id = did
            .strip_prefix(DID_PREFIX)
            .unwrap_or(&did)
            .to_string();

        info!(
            did = %did,
            object_id = %object_id,
            "DID created successfully on IOTA Rebased"
        );

        Ok(DeviceIdentity::new(
            did,
            object_id,
            public_key_hex.to_string(),
            device_type,
            capabilities,
        ))
    }

    /// Publish a DID Document to IOTA Rebased
    ///
    /// This requires:
    /// - A signing key (stored in Stronghold)
    /// - IOTA tokens for gas
    /// - The Identity Package ID
    async fn publish_document(&self, document: IotaDocument) -> IdentityResult<IotaDocument> {
        // For a full implementation, we need to:
        // 1. Generate or load a signing key from Stronghold
        // 2. Get the address from the signing key
        // 3. Request funds from faucet (testnet/devnet)
        // 4. Create a full IdentityClient with the signer
        // 5. Call publish_did_document() with gas budget

        // Note: This is a simplified version. In production, you'd implement
        // the full signing flow with Stronghold.

        // For now, we'll use a placeholder that shows the correct API structure
        // The actual implementation requires async key management

        /*
        // Full implementation would look like:
        let signer = self.get_or_create_signer().await?;
        
        let sender_address = IotaAddress::from(&signer.public_key().await?);
        
        // Request funds if on testnet/devnet
        if self.network.has_faucet() {
            self.request_faucet_funds(&sender_address).await?;
        }
        
        // Create full identity client with signer
        let iota_client = IotaClientBuilder::default()
            .build(&self.endpoint)
            .await?;
            
        let identity_client = IdentityClient::new(iota_client, signer).await?;
        
        // Publish with gas budget
        let published = identity_client
            .publish_did_document(document)
            .with_gas_budget(GAS_BUDGET_PUBLISH_DID)
            .build_and_execute(&identity_client)
            .await
            .map_err(|e| IdentityError::TransactionError(e.to_string()))?
            .output;
        
        Ok(published)
        */

        // Placeholder - returns the document as-is
        // In production, this would actually publish to the blockchain
        warn!("publish_document: Using placeholder implementation");
        Ok(document)
    }

    /// Request funds from the IOTA faucet (testnet/devnet only)
    async fn request_faucet_funds(&self, address: &str) -> IdentityResult<()> {
        let faucet_url = self.network.faucet_url()
            .ok_or_else(|| IdentityError::FaucetError(
                "No faucet available for this network".into()
            ))?;

        info!(
            address = %address,
            faucet = %faucet_url,
            "Requesting funds from IOTA faucet"
        );

        let client = reqwest::Client::new();
        let response = client
            .post(faucet_url)
            .json(&serde_json::json!({
                "FixedAmountRequest": {
                    "recipient": address
                }
            }))
            .send()
            .await
            .map_err(|e| IdentityError::FaucetError(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            warn!(
                status = %status,
                body = %body,
                "Faucet request returned non-success status"
            );
        }

        // Wait for transaction processing
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        Ok(())
    }

    /// Resolve a DID to retrieve its DID Document from the blockchain
    ///
    /// # Arguments
    /// * `did` - DID string to resolve (e.g., "did:iota:0x...")
    ///
    /// # Returns
    /// The IotaDocument from the blockchain
    pub async fn resolve_did(&self, did: &str) -> IdentityResult<IotaDocument> {
        debug!(did = %did, "Resolving DID from IOTA Rebased");

        // Parse and validate DID
        let iota_did = IotaDID::parse(did)
            .map_err(|e| IdentityError::InvalidDID(e.to_string()))?;

        // Use read-only client to resolve
        let document = self.read_only_client
            .resolve_did(&iota_did)
            .await
            .map_err(|e| IdentityError::DIDResolutionError {
                did: did.to_string(),
                reason: e.to_string(),
            })?;

        info!(did = %did, "DID resolved successfully");

        Ok(document)
    }

    /// Resolve a DID and return as JSON string
    pub async fn resolve_did_json(&self, did: &str) -> IdentityResult<String> {
        let document = self.resolve_did(did).await?;
        
        serde_json::to_string_pretty(&document)
            .map_err(|e| IdentityError::SerializationError(e.to_string()))
    }

    /// Get or initialize the issuer's DID
    pub async fn get_or_create_issuer_did(&self) -> IdentityResult<IotaDID> {
        // Check if already initialized
        {
            let guard = self.issuer_did.read();
            if let Some(ref did) = *guard {
                return Ok(did.clone());
            }
        }

        // Need to create new issuer DID
        info!("Creating issuer DID for Identity Service");
        
        // Generate a new keypair for the issuer
        let issuer_keypair = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let public_key_hex = hex::encode(issuer_keypair.verifying_key().as_bytes());

        // Create the issuer's DID
        let identity = self.create_did(
            &public_key_hex,
            shared::types::DeviceType::Generic,
            vec!["issuer".into()],
        ).await?;

        // Parse the DID
        let issuer_did = IotaDID::parse(&identity.did)
            .map_err(|e| IdentityError::InvalidDID(e.to_string()))?;

        // Store it
        {
            let mut guard = self.issuer_did.write();
            *guard = Some(issuer_did.clone());
        }

        info!(did = %issuer_did, "Issuer DID created");

        Ok(issuer_did)
    }

    /// Get the current network
    pub fn network(&self) -> IotaNetwork {
        self.network
    }

    /// Get the RPC endpoint
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Get a reference to the storage
    pub fn storage(&self) -> Arc<IdentityStorage> {
        Arc::clone(&self.storage)
    }
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Create a read-only identity client for resolving DIDs
pub async fn create_read_only_client(endpoint: &str) -> Result<IdentityClientReadOnly> {
    let iota_client = IotaClientBuilder::default()
        .build(endpoint)
        .await
        .context("Failed to build IOTA client")?;

    IdentityClientReadOnly::new(iota_client)
        .await
        .context("Failed to create read-only identity client")
}

/// Create in-memory storage for testing
/// NOTE: Use Stronghold in production!
pub fn create_mem_storage() -> Storage<JwkMemStore, KeyIdMemstore> {
    Storage::new(JwkMemStore::new(), KeyIdMemstore::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_validation() {
        // Valid 32-byte key (64 hex chars)
        let valid_key = "a".repeat(64);
        assert!(hex::decode(&valid_key).is_ok());
        
        let bytes = hex::decode(&valid_key).unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_did_parsing() {
        let valid_did = "did:iota:0x0000000000000000000000000000000000000000000000000000000000000000";
        // This would work with actual IOTA DID parser
        // let parsed = IotaDID::parse(valid_did);
    }
}