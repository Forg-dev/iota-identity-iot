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
use identity_iota::document::Service;
use identity_iota::core::Url;
use identity_iota::did::DID;

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
use identity_iota::verification::{MethodScope, VerificationMethod};
use identity_iota::verification::jwk::Jwk;

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
    pub public_key_jwk: Jwk,
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

/// Result of creating an issuer DID, including the transaction key for persistence
#[derive(Debug, Clone)]
pub struct IssuerCreationResult {
    /// The created DID string
    pub did: String,
    /// The transaction private key (hex encoded) for persisting control
    pub tx_private_key_hex: String,
    /// The verification method fragment
    pub fragment: String,
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
        let public_key_jwk = control_info.public_key_jwk.to_public()
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
    /// 
    /// NOTE: For issuer DIDs, we need to use create_issuer_did_with_signing_key instead
    /// to ensure the DID Document contains the CredentialIssuer's public key.
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

        // Generate a new signing key for the transaction (this is for signing the blockchain tx)
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
                public_key_jwk: generate_result.jwk.clone(),
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
    
    // =========================================================================
    // REVOCATIONBITMAP2022 SERVICE MANAGEMENT
    // =========================================================================
    
    /// Update the RevocationBitmap2022 service in a DID Document
    /// 
    /// This method updates the issuer's DID Document with the new bitmap data URL
    /// and publishes the update on-chain.
    /// 
    /// # Arguments
    /// * `did` - The DID to update (must be controlled by this service)
    /// * `service_fragment` - Fragment for the service (e.g., "revocation")
    /// * `bitmap_data_url` - The data URL containing the encoded bitmap
    /// 
    /// # Returns
    /// Ok(()) if successful, or an error
    pub async fn update_revocation_service(
        &self,
        did: &str,
        service_fragment: &str,
        bitmap_data_url: &str,
    ) -> IdentityResult<()> {
        info!(did = %did, fragment = %service_fragment, "Updating RevocationBitmap2022 service on-chain");
        
        // Get control info for the DID
        let control_info = {
            let control_map = self.did_control_info.read();
            control_map.get(did).cloned()
        }.ok_or_else(|| IdentityError::UnauthorizedOperation(
            format!("No control info for DID: {}. Cannot update DIDs not created by this service.", did)
        ))?;
        
        if control_info.deactivated {
            return Err(IdentityError::DIDAlreadyDeactivated(did.to_string()));
        }
        
        // Resolve current document
        let mut current_doc = self.resolve_did(did).await?;
        
        // Create the service ID
        let service_id = current_doc.id().to_url().join(&format!("#{}", service_fragment))
            .map_err(|e| IdentityError::DIDUpdateError(format!(
                "Failed to create service ID: {}", e
            )))?;
        
        // Remove existing revocation service if present
        let _ = current_doc.remove_service(&service_id);
        
        // Create the new service with RevocationBitmap2022 type
        let service_endpoint = Url::parse(bitmap_data_url)
            .map_err(|e| IdentityError::DIDUpdateError(format!(
                "Invalid bitmap data URL: {}", e
            )))?;
        
        let service = Service::builder(Default::default())
            .id(service_id.clone())
            .type_("RevocationBitmap2022")
            .service_endpoint(service_endpoint)
            .build()
            .map_err(|e| IdentityError::DIDUpdateError(format!(
                "Failed to build service: {}", e
            )))?;
        
        // Insert the new service
        current_doc.insert_service(service)
            .map_err(|e| IdentityError::DIDUpdateError(format!(
                "Failed to insert service: {}", e
            )))?;
        
        // Create identity client for publishing
        let (identity_client, sender_address) = self.create_identity_client_for_did(&control_info).await?;
        
        // Request funds if needed
        if self.network.has_faucet() {
            info!(sender_address = %sender_address, "Requesting funds for revocation bitmap update");
            request_funds(&sender_address)
                .await
                .map_err(|e| IdentityError::FaucetError(format!(
                    "Failed to request funds: {}", e
                )))?;
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        }
        
        // Publish the updated document
        info!("Publishing RevocationBitmap2022 update to IOTA Rebased...");
        
        identity_client
            .publish_did_document_update(current_doc, GAS_BUDGET_UPDATE_DID)
            .await
            .map_err(|e| IdentityError::DIDUpdateError(format!(
                "Failed to publish DID document update: {}", e
            )))?;
        
        info!(did = %did, "RevocationBitmap2022 service updated successfully on-chain");
        
        Ok(())
    }
    
    /// Add initial RevocationBitmap2022 service to a newly created issuer DID
    /// 
    /// This should be called after creating the issuer DID to set up the revocation service.
    pub async fn add_revocation_service_to_issuer(
        &self,
        bitmap_data_url: &str,
    ) -> IdentityResult<String> {
        let issuer_did = {
            let guard = self.issuer_did.read();
            guard.clone()
        }.ok_or_else(|| IdentityError::DIDCreationError(
            "Issuer DID not initialized".into()
        ))?;
        
        let did_str = issuer_did.to_string();
        
        self.update_revocation_service(&did_str, "revocation", bitmap_data_url).await?;
        
        Ok(did_str)
    }
    
    /// Get the issuer DID string if initialized
    pub fn get_issuer_did_string(&self) -> Option<String> {
        let guard = self.issuer_did.read();
        guard.as_ref().map(|d| d.to_string())
    }
    
    /// Set the issuer DID from a string (used when loading from storage)
    pub fn set_issuer_did_from_string(&self, did_str: &str) -> IdentityResult<()> {
        let iota_did = IotaDID::parse(did_str)
            .map_err(|e| IdentityError::InvalidDID(e.to_string()))?;
        
        let mut guard = self.issuer_did.write();
        *guard = Some(iota_did);
        
        info!(did = %did_str, "Issuer DID set from storage");
        
        Ok(())
    }
    
    /// Restore control info for an issuer DID from stored transaction key
    /// This allows the service to modify the DID after a restart
    pub async fn restore_issuer_control_info(
        &self,
        did_str: &str,
        tx_private_key_hex: &str,
        fragment: &str,
    ) -> IdentityResult<()> {
        info!(did = %did_str, "Restoring control info for issuer DID from stored key");
        
        // Decode the transaction private key
        let tx_key_bytes = hex::decode(tx_private_key_hex)
            .map_err(|e| IdentityError::InvalidPublicKey(format!("Invalid tx key hex: {}", e)))?;
        
        if tx_key_bytes.len() != 32 {
            return Err(IdentityError::InvalidPublicKey(
                format!("Expected 32 bytes for Ed25519 private key, got {}", tx_key_bytes.len())
            ));
        }
        
        // Create the Ed25519 signing key from the stored bytes
        let tx_key_array: [u8; 32] = tx_key_bytes.try_into()
            .map_err(|_| IdentityError::InvalidPublicKey("Key must be 32 bytes".into()))?;
        
        // Import the key into storage using the JwkMemStore
        // We need to create a JWK with both public and private parts
        use base64::Engine;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&tx_key_array);
        let verifying_key = signing_key.verifying_key();
        
        // Create JWK with private key ('d' parameter)
        let d_value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&tx_key_array);
        let x_value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(verifying_key.as_bytes());
        
        let jwk_json = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "x": x_value,
            "d": d_value
        });
        
        let private_jwk: identity_iota::verification::jwk::Jwk = serde_json::from_value(jwk_json)
            .map_err(|e| IdentityError::DIDCreationError(format!(
                "Failed to create JWK from stored key: {}", e
            )))?;
        
        // Insert the key into storage
        let key_id = self.storage
            .key_storage()
            .insert(private_jwk.clone())
            .await
            .map_err(|e| IdentityError::DIDCreationError(format!(
                "Failed to insert restored key into storage: {}", e
            )))?;
        
        // Store control info for this DID
        let control_info = DIDControlInfo {
            did: did_str.to_string(),
            key_id,
            public_key_jwk: private_jwk, // Store the full JWK (includes private part)
            fragment: fragment.to_string(),
            deactivated: false,
        };
        
        let mut control_map = self.did_control_info.write();
        control_map.insert(did_str.to_string(), control_info);
        
        info!(did = %did_str, "Control info restored successfully");
        
        Ok(())
    }
    
    /// Create issuer DID on-chain using a specific public key
    /// This ensures the DID Document contains the same key used for signing credentials
    /// Returns the DID and the transaction key needed to control it
    pub async fn create_issuer_did_with_key(&self, public_key_hex: &str) -> IdentityResult<IssuerCreationResult> {
        // Check if already initialized
        {
            let guard = self.issuer_did.read();
            if let Some(ref did) = *guard {
                // Already initialized - return without tx key (caller should have it)
                return Ok(IssuerCreationResult {
                    did: did.to_string(),
                    tx_private_key_hex: String::new(), // Empty - already initialized
                    fragment: "issuer-key-1".to_string(),
                });
            }
        }

        info!(public_key = %public_key_hex, "Creating issuer DID with CredentialIssuer's public key");
        
        // Validate the provided public key
        let public_key_bytes = hex::decode(public_key_hex)
            .map_err(|e| IdentityError::InvalidPublicKey(e.to_string()))?;

        if public_key_bytes.len() != 32 {
            return Err(IdentityError::InvalidPublicKey(
                format!("Expected 32 bytes, got {}", public_key_bytes.len())
            ));
        }

        // Generate a transaction signing key manually (so we have access to the private key)
        // This is different from the credential signing key
        use base64::Engine;
        let tx_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let tx_verifying_key = tx_signing_key.verifying_key();
        
        // Create JWK with private key ('d' parameter) and algorithm
        let tx_private_bytes = tx_signing_key.to_bytes();
        let d_value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&tx_private_bytes);
        let x_value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(tx_verifying_key.as_bytes());
        
        let tx_jwk_json = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "x": x_value,
            "d": d_value
        });
        
        let tx_private_jwk: Jwk = serde_json::from_value(tx_jwk_json)
            .map_err(|e| IdentityError::DIDCreationError(format!(
                "Failed to create JWK: {}", e
            )))?;
        
        // Store the private key hex for persistence
        let tx_private_key_hex_for_storage = hex::encode(&tx_private_bytes);
        
        // Insert the key into storage
        let tx_key_id = self.storage
            .key_storage()
            .insert(tx_private_jwk.clone())
            .await
            .map_err(|e| IdentityError::DIDCreationError(format!(
                "Failed to insert transaction key into storage: {}", e
            )))?;

        let tx_public_key_jwk = tx_private_jwk.to_public()
            .ok_or_else(|| IdentityError::DIDCreationError(
                "Failed to derive public key from JWK".into()
            ))?;

        // Create StorageSigner for signing blockchain transactions
        let signer = StorageSigner::new(
            self.storage.as_ref(),
            tx_key_id.clone(),
            tx_public_key_jwk.clone(),
        );

        // Build IOTA client
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

        // Get sender address and request funds
        let sender_address = identity_client.address();
        
        info!(sender_address = %sender_address, "Requesting funds from faucet for issuer DID");

        if self.network.has_faucet() {
            request_funds(&sender_address)
                .await
                .map_err(|e| IdentityError::FaucetError(format!(
                    "Failed to request funds: {}", e
                )))?;
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        }

        // Create unpublished DID Document
        let network_name = identity_client.network();
        let mut unpublished_doc = IotaDocument::new(network_name);

        // Create JWK from the provided public key (CredentialIssuer's key)
        // This is the key that will be used to verify credential signatures
        let issuer_jwk = create_ed25519_jwk_from_bytes(&public_key_bytes)?;
        
        // Insert the CredentialIssuer's public key as a verification method
        let method = VerificationMethod::new_from_jwk(
            unpublished_doc.id().clone(),
            issuer_jwk,
            Some("issuer-key-1"),
        ).map_err(|e| IdentityError::DIDCreationError(format!(
            "Failed to create verification method: {}", e
        )))?;
        
        unpublished_doc.insert_method(method, MethodScope::VerificationMethod)
            .map_err(|e| IdentityError::DIDCreationError(format!(
                "Failed to insert verification method: {}", e
            )))?;

        // Publish DID Document to blockchain
        info!("Publishing issuer DID Document to IOTA Rebased...");
        
        let published_doc = identity_client
            .publish_did_document(unpublished_doc)
            .with_gas_budget(GAS_BUDGET_PUBLISH_DID)
            .build_and_execute(&identity_client)
            .await
            .map_err(|e| IdentityError::DIDCreationError(format!(
                "Failed to publish issuer DID document: {}", e
            )))?
            .output;

        let did_str = published_doc.id().to_string();

        // Store control info for this DID
        {
            let control_info = DIDControlInfo {
                did: did_str.clone(),
                key_id: tx_key_id.clone(),
                public_key_jwk: tx_private_jwk.clone(),
                fragment: "issuer-key-1".to_string(),
                deactivated: false,
            };
            let mut control_map = self.did_control_info.write();
            control_map.insert(did_str.clone(), control_info);
        }

        // Set as issuer DID
        let issuer_did = IotaDID::parse(&did_str)
            .map_err(|e| IdentityError::InvalidDID(e.to_string()))?;

        {
            let mut guard = self.issuer_did.write();
            *guard = Some(issuer_did.clone());
        }

        info!(did = %did_str, "Issuer DID created with CredentialIssuer's public key");

        Ok(IssuerCreationResult {
            did: did_str,
            tx_private_key_hex: tx_private_key_hex_for_storage,
            fragment: "issuer-key-1".to_string(),
        })
    }
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Extract the private key from a JWK (the 'd' parameter)
/// Returns the private key as a hex string
#[allow(dead_code)]
fn extract_private_key_from_jwk(jwk: &identity_iota::verification::jwk::Jwk) -> IdentityResult<String> {
    use base64::Engine;
    
    // Get the 'd' parameter which contains the private key
    let d_param = jwk.try_okp_params()
        .map_err(|e| IdentityError::DIDCreationError(format!(
            "JWK is not an OKP key: {}", e
        )))?
        .d
        .as_ref()
        .ok_or_else(|| IdentityError::DIDCreationError(
            "JWK does not contain private key ('d' parameter)".into()
        ))?;
    
    // Decode from base64url
    let private_key_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(d_param.as_bytes())
        .map_err(|e| IdentityError::DIDCreationError(format!(
            "Failed to decode private key from JWK: {}", e
        )))?;
    
    // Return as hex
    Ok(hex::encode(private_key_bytes))
}

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

/// Create an Ed25519 JWK from raw public key bytes
/// 
/// This is used to insert the CredentialIssuer's public key into a DID Document.
fn create_ed25519_jwk_from_bytes(public_key_bytes: &[u8]) -> IdentityResult<Jwk> {
    use base64::Engine;
    
    // Ensure we have exactly 32 bytes
    if public_key_bytes.len() != 32 {
        return Err(IdentityError::InvalidPublicKey(
            format!("Expected 32 bytes for Ed25519 public key, got {}", public_key_bytes.len())
        ));
    }
    
    // Encode the public key as base64url (required for JWK 'x' parameter)
    let x_value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key_bytes);
    
    // Create the JWK JSON
    let jwk_json = serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": x_value
    });
    
    // Parse into a Jwk struct
    let jwk: Jwk = serde_json::from_value(jwk_json)
        .map_err(|e| IdentityError::DIDCreationError(format!(
            "Failed to create JWK from public key: {}", e
        )))?;
    
    Ok(jwk)
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
    
    #[test]
    fn test_create_ed25519_jwk() {
        let test_bytes = [0u8; 32];
        let jwk = create_ed25519_jwk_from_bytes(&test_bytes);
        assert!(jwk.is_ok());
    }
}