//! # DID Manager for IOTA Rebased
//!
//! This module handles all DID operations on IOTA Rebased blockchain:
//! - Creating new DIDs (publishing DID Documents)
//! - Resolving existing DIDs
//! - Updating DID Documents (key rotation)
//! - Deactivating DIDs (on-chain revocation)

use anyhow::{Context, Result};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

// Core Identity types
use identity_iota::iota::{IotaDocument, IotaDID};

// Storage for cryptographic operations
use identity_iota::storage::{
    JwkDocumentExt,
    JwkMemStore,
    JwkStorage,
    KeyIdMemstore,
    Storage,
};

// Verification and signing
use identity_iota::verification::jws::JwsAlgorithm;
use identity_iota::verification::MethodScope;

// IOTA Rebased clients
use identity_iota::iota::rebased::client::{IdentityClient, IdentityClientReadOnly};

// Faucet utility for testnet/devnet
use identity_iota::iota::rebased::utils::request_funds;

// IotaClientBuilder via re-export
use identity_iota::iota_interaction::IotaClientBuilder;
use identity_iota::iota_interaction::types::base_types::IotaAddress;

// StorageSigner for signing transactions
use identity_storage::{KeyType, StorageSigner, KeyId};

// Re-export shared types
use shared::{
    config::{IdentityServiceConfig, IotaNetwork},
    error::{IdentityError, IdentityResult},
    types::DeviceIdentity,
};

/// Type alias for the storage backend
pub type IdentityStorage = Storage<JwkMemStore, KeyIdMemstore>;

/// Gas budget for publishing a new DID document (in IOTA nanos)
const GAS_BUDGET_PUBLISH_DID: u64 = 50_000_000;

/// Gas budget for updating/deactivating a DID document
const GAS_BUDGET_UPDATE_DID: u64 = 50_000_000;

/// Information about a DID's control key stored for later operations
#[derive(Debug, Clone)]
pub struct DIDControlInfo {
    /// The DID string
    pub did: String,
    /// Key ID in the storage for the signing key
    pub key_id: KeyId,
    /// The public key JWK for creating signers
    pub public_key_jwk: identity_iota::storage::JwkGenOutput,
    /// The fragment of the verification method
    pub fragment: String,
    /// Whether this DID has been deactivated
    pub deactivated: bool,
}

/// DID Manager for IOTA Rebased
pub struct DIDManager {
    /// Read-only client for resolving DIDs
    read_only_client: IdentityClientReadOnly,
    
    /// Secure storage for cryptographic keys
    storage: Arc<IdentityStorage>,
    
    /// Issuer's DID (this service's identity)
    issuer_did: RwLock<Option<IotaDID>>,
    
    /// Control info for DIDs we can manage
    did_control_info: RwLock<HashMap<String, DIDControlInfo>>,
    
    /// Network configuration
    network: IotaNetwork,
    
    /// RPC endpoint
    endpoint: String,
    
    /// Identity Package ID
    package_id: String,
}

impl DIDManager {
    /// Create a new DID Manager for IOTA Rebased
    pub async fn new(config: &IdentityServiceConfig) -> Result<Self> {
        let endpoint = config.endpoint().to_string();
        let package_id = config.package_id()?.to_string();
        
        info!(
            network = %config.network,
            endpoint = %endpoint,
            package_id = %package_id,
            "Initializing DID Manager for IOTA Rebased"
        );

        let iota_client = IotaClientBuilder::default()
            .build(&endpoint)
            .await
            .context("Failed to build IOTA Rebased client")?;

        let pkg_id = package_id.parse()
            .context("Failed to parse package ID")?;

        let read_only_client = IdentityClientReadOnly::new_with_pkg_id(iota_client, pkg_id)
            .await
            .context("Failed to create read-only identity client")?;

        let storage = Self::setup_storage(config).await?;

        info!("DID Manager initialized successfully for IOTA Rebased");

        Ok(Self {
            read_only_client,
            storage: Arc::new(storage),
            issuer_did: RwLock::new(None),
            did_control_info: RwLock::new(HashMap::new()),
            network: config.network,
            endpoint,
            package_id,
        })
    }

    async fn setup_storage(_config: &IdentityServiceConfig) -> Result<IdentityStorage> {
        info!("Setting up in-memory key storage (development mode)");
        warn!("Keys are stored in-memory and will be lost on restart!");

        let jwk_store = JwkMemStore::new();
        let key_id_store = KeyIdMemstore::new();

        Ok(Storage::new(jwk_store, key_id_store))
    }

    /// Helper to create an IdentityClient from stored control info
    async fn create_identity_client_for_did(
        &self,
        control_info: &DIDControlInfo,
    ) -> IdentityResult<(IdentityClient<StorageSigner<'_, JwkMemStore, KeyIdMemstore>>, IotaAddress)> {
        let public_key_jwk = control_info.public_key_jwk.jwk.to_public()
            .ok_or_else(|| IdentityError::DIDUpdateError(
                "Failed to derive public key from stored JWK".into()
            ))?;
        
        let signer = StorageSigner::new(
            self.storage.as_ref(),
            control_info.key_id.clone(),
            public_key_jwk,
        );
        
        let iota_client = IotaClientBuilder::default()
            .build(&self.endpoint)
            .await
            .map_err(|e| IdentityError::DIDUpdateError(format!(
                "Failed to build IOTA client: {}", e
            )))?;
        
        let pkg_id = self.package_id.parse()
            .map_err(|e| IdentityError::DIDUpdateError(format!(
                "Invalid package ID: {:?}", e
            )))?;
        
        let read_client = IdentityClientReadOnly::new_with_pkg_id(iota_client, pkg_id)
            .await
            .map_err(|e| IdentityError::DIDUpdateError(format!(
                "Failed to create read-only client: {}", e
            )))?;
        
        let identity_client = IdentityClient::new(read_client, signer)
            .await
            .map_err(|e| IdentityError::DIDUpdateError(format!(
                "Failed to create identity client: {}", e
            )))?;
        
        // Get sender address from the identity client
        let sender_address = identity_client.address();
        
        Ok((identity_client, sender_address))
    }

    /// Create a new DID for a device on IOTA Rebased
    pub async fn create_did(
        &self,
        public_key_hex: &str,
        device_type: shared::types::DeviceType,
        capabilities: Vec<String>,
    ) -> IdentityResult<DeviceIdentity> {
        info!(
            public_key_len = public_key_hex.len(),
            device_type = ?device_type,
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

        // Generate a new signing key for the transaction
        let generate_result = self.storage
            .key_storage()
            .generate(KeyType::new("Ed25519"), JwsAlgorithm::EdDSA)
            .await
            .map_err(|e| IdentityError::DIDCreationError(format!(
                "Failed to generate signing key: {}", e
            )))?;

        let public_key_jwk = generate_result.jwk.to_public()
            .ok_or_else(|| IdentityError::DIDCreationError(
                "Failed to derive public key from JWK".into()
            ))?;

        // Create StorageSigner for signing transactions
        let signer = StorageSigner::new(
            self.storage.as_ref(),
            generate_result.key_id.clone(),
            public_key_jwk.clone(),
        );

        // Build IOTA client for publishing
        let iota_client = IotaClientBuilder::default()
            .build(&self.endpoint)
            .await
            .map_err(|e| IdentityError::DIDCreationError(format!(
                "Failed to build IOTA client: {}", e
            )))?;

        let pkg_id = self.package_id.parse()
            .map_err(|e| IdentityError::DIDCreationError(format!(
                "Invalid package ID: {:?}", e
            )))?;

        let read_client = IdentityClientReadOnly::new_with_pkg_id(iota_client, pkg_id)
            .await
            .map_err(|e| IdentityError::DIDCreationError(format!(
                "Failed to create read-only client: {}", e
            )))?;

        let identity_client = IdentityClient::new(read_client, signer)
            .await
            .map_err(|e| IdentityError::DIDCreationError(format!(
                "Failed to create identity client: {}", e
            )))?;

        // Get sender address from the identity client
        let sender_address = identity_client.address();
        
        info!(sender_address = %sender_address, "Requesting funds from faucet");

        // Request funds from faucet (testnet/devnet only)
        if self.network.has_faucet() {
            request_funds(&sender_address)
                .await
                .map_err(|e| IdentityError::FaucetError(format!(
                    "Failed to request funds: {}", e
                )))?;

            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            debug!("Funds received from faucet");
        }

        // Create unpublished DID Document
        let network_name = identity_client.network();
        let mut unpublished_doc = IotaDocument::new(network_name);

        // Generate and add verification method
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

        // Publish DID Document to blockchain
        info!("Publishing DID Document to IOTA Rebased...");
        
        let published_doc = identity_client
            .publish_did_document(unpublished_doc)
            .with_gas_budget(GAS_BUDGET_PUBLISH_DID)
            .build_and_execute(&identity_client)
            .await
            .map_err(|e| IdentityError::DIDCreationError(format!(
                "Failed to publish DID document: {}", e
            )))?
            .output;

        let did = published_doc.id().to_string();
        let object_id = published_doc.id().tag_str().to_string();

        // Store control info for this DID
        {
            let control_info = DIDControlInfo {
                did: did.clone(),
                key_id: generate_result.key_id.clone(),
                public_key_jwk: generate_result.clone(),
                fragment: fragment.clone(),
                deactivated: false,
            };
            let mut control_map = self.did_control_info.write();
            control_map.insert(did.clone(), control_info);
        }

        info!(did = %did, object_id = %object_id, "DID created successfully");

        Ok(DeviceIdentity::new(
            did,
            object_id,
            public_key_hex.to_string(),
            device_type,
            capabilities,
        ))
    }

    /// Resolve a DID to retrieve its DID Document from the blockchain
    pub async fn resolve_did(&self, did: &str) -> IdentityResult<IotaDocument> {
        debug!(did = %did, "Resolving DID from IOTA Rebased");

        let iota_did = IotaDID::parse(did)
            .map_err(|e| IdentityError::InvalidDID(e.to_string()))?;

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
        {
            let guard = self.issuer_did.read();
            if let Some(ref did) = *guard {
                return Ok(did.clone());
            }
        }

        info!("Creating issuer DID for Identity Service");
        
        let issuer_keypair = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let public_key_hex = hex::encode(issuer_keypair.verifying_key().as_bytes());

        let identity = self.create_did(
            &public_key_hex,
            shared::types::DeviceType::Generic,
            vec!["issuer".into()],
        ).await?;

        let issuer_did = IotaDID::parse(&identity.did)
            .map_err(|e| IdentityError::InvalidDID(e.to_string()))?;

        {
            let mut guard = self.issuer_did.write();
            *guard = Some(issuer_did.clone());
        }

        info!(did = %issuer_did, "Issuer DID created");

        Ok(issuer_did)
    }

    /// Check if we have control over a DID
    pub fn has_control(&self, did: &str) -> bool {
        let control_map = self.did_control_info.read();
        control_map.contains_key(did)
    }
    
    /// Get control info for a DID
    pub fn get_control_info(&self, did: &str) -> Option<DIDControlInfo> {
        let control_map = self.did_control_info.read();
        control_map.get(did).cloned()
    }

    // =========================================================================
    // ON-CHAIN DEACTIVATION (REVOCATION)
    // =========================================================================
    
    /// Deactivate a DID on the blockchain
    pub async fn deactivate_did(&self, did: &str) -> IdentityResult<()> {
        info!(did = %did, "Deactivating DID on IOTA Rebased");
        
        let control_info = {
            let control_map = self.did_control_info.read();
            control_map.get(did).cloned()
        }.ok_or_else(|| IdentityError::UnauthorizedOperation(
            format!("No control info for DID: {}. Cannot deactivate DIDs not created by this service.", did)
        ))?;
        
        if control_info.deactivated {
            return Err(IdentityError::DIDAlreadyDeactivated(did.to_string()));
        }
        
        let iota_did = IotaDID::parse(did)
            .map_err(|e| IdentityError::InvalidDID(e.to_string()))?;
        
        // Create identity client and get sender address
        let (identity_client, sender_address) = self.create_identity_client_for_did(&control_info).await?;
        
        // Request funds using the sender address
        if self.network.has_faucet() {
            info!(sender_address = %sender_address, "Requesting funds for deactivation");
            request_funds(&sender_address)
                .await
                .map_err(|e| IdentityError::FaucetError(format!(
                    "Failed to request funds: {}", e
                )))?;
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        }
        
        info!("Publishing deactivation to IOTA Rebased...");
        
        identity_client
            .deactivate_did_output(&iota_did, GAS_BUDGET_UPDATE_DID)
            .await
            .map_err(|e| IdentityError::DIDUpdateError(format!(
                "Failed to deactivate DID document: {}", e
            )))?;
        
        {
            let mut control_map = self.did_control_info.write();
            if let Some(info) = control_map.get_mut(did) {
                info.deactivated = true;
            }
        }
        
        info!(did = %did, "DID deactivated successfully on IOTA Rebased");
        
        Ok(())
    }

    // =========================================================================
    // ON-CHAIN KEY ROTATION
    // =========================================================================
    
    /// Rotate the verification key for a DID on the blockchain
    pub async fn rotate_key(
        &self,
        did: &str,
        new_public_key_hex: &str,
    ) -> IdentityResult<String> {
        info!(did = %did, "Rotating key for DID on IOTA Rebased");
        
        let new_public_key_bytes = hex::decode(new_public_key_hex)
            .map_err(|e| IdentityError::InvalidPublicKey(e.to_string()))?;
        
        if new_public_key_bytes.len() != 32 {
            return Err(IdentityError::InvalidPublicKey(
                format!("Expected 32 bytes, got {}", new_public_key_bytes.len())
            ));
        }
        
        let control_info = {
            let control_map = self.did_control_info.read();
            control_map.get(did).cloned()
        }.ok_or_else(|| IdentityError::UnauthorizedOperation(
            format!("No control info for DID: {}. Cannot rotate keys for DIDs not created by this service.", did)
        ))?;
        
        if control_info.deactivated {
            return Err(IdentityError::DIDAlreadyDeactivated(did.to_string()));
        }
        
        let mut current_doc = self.resolve_did(did).await?;
        
        // Create identity client and get sender address
        let (identity_client, sender_address) = self.create_identity_client_for_did(&control_info).await?;
        
        // Request funds using the sender address
        if self.network.has_faucet() {
            info!(sender_address = %sender_address, "Requesting funds for key rotation");
            request_funds(&sender_address)
                .await
                .map_err(|e| IdentityError::FaucetError(format!(
                    "Failed to request funds: {}", e
                )))?;
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        }
        
        // Generate new verification method in the document
        let new_fragment = current_doc
            .generate_method(
                self.storage.as_ref(),
                JwkMemStore::ED25519_KEY_TYPE,
                JwsAlgorithm::EdDSA,
                None,
                MethodScope::VerificationMethod,
            )
            .await
            .map_err(|e| IdentityError::DIDUpdateError(format!(
                "Failed to generate new verification method: {}", e
            )))?;
        
        debug!(new_fragment = %new_fragment, "New verification method generated");
        
        info!("Publishing key rotation to IOTA Rebased...");
        
        identity_client
            .publish_did_document_update(current_doc, GAS_BUDGET_UPDATE_DID)
            .await
            .map_err(|e| IdentityError::DIDUpdateError(format!(
                "Failed to publish DID document update: {}", e
            )))?;
        
        {
            let mut control_map = self.did_control_info.write();
            if let Some(info) = control_map.get_mut(did) {
                info.fragment = new_fragment.clone();
            }
        }
        
        info!(did = %did, new_fragment = %new_fragment, "Key rotation completed successfully");
        
        Ok(new_fragment)
    }
    
    /// Check if a DID has been deactivated
    pub async fn is_deactivated(&self, did: &str) -> IdentityResult<bool> {
        if let Some(info) = self.get_control_info(did) {
            if info.deactivated {
                return Ok(true);
            }
        }
        
        match self.resolve_did(did).await {
            Ok(doc) => {
                Ok(doc.metadata.deactivated.unwrap_or(false))
            }
            Err(IdentityError::DIDNotFound(_)) => Ok(true),
            Err(e) => Err(e),
        }
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
pub async fn create_read_only_client(endpoint: &str, package_id: &str) -> Result<IdentityClientReadOnly> {
    let iota_client = IotaClientBuilder::default()
        .build(endpoint)
        .await
        .context("Failed to build IOTA client")?;

    let pkg_id = package_id.parse()
        .context("Invalid package ID")?;

    IdentityClientReadOnly::new_with_pkg_id(iota_client, pkg_id)
        .await
        .context("Failed to create read-only identity client")
}

/// Create in-memory storage for testing
pub fn create_mem_storage() -> Storage<JwkMemStore, KeyIdMemstore> {
    Storage::new(JwkMemStore::new(), KeyIdMemstore::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_validation() {
        let valid_key = "a".repeat(64);
        assert!(hex::decode(&valid_key).is_ok());
        
        let bytes = hex::decode(&valid_key).unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_did_format() {
        let example_did = "did:iota:testnet:0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(example_did.starts_with("did:iota:"));
    }
}