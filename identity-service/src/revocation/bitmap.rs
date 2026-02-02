//! # On-Chain Revocation using RevocationBitmap2022
//!
//! This module implements the W3C RevocationBitmap2022 standard for
//! on-chain credential revocation on IOTA Rebased.
//!
//! ## How it works
//!
//! 1. The issuer's DID Document contains a service of type `RevocationBitmap2022`
//! 2. Each credential has a `credentialStatus` with a `revocationBitmapIndex`
//! 3. To revoke: set the bit at that index to 1 and publish updated DID Document
//! 4. To verify: check the bit at the credential's index in the issuer's bitmap
//!
//! ## Specification
//!
//! See: https://wiki.iota.org/identity.rs/references/specifications/revocation-bitmap-2022/

use chrono::{DateTime, Utc};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use parking_lot::RwLock;
use roaring::RoaringBitmap;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU32, Ordering};
use tracing::{debug, info, warn};

use shared::types::CredentialStatus;

/// Service type constant for RevocationBitmap2022
pub const REVOCATION_SERVICE_TYPE: &str = "RevocationBitmap2022";

/// Fragment for the revocation service in DID Document
pub const REVOCATION_SERVICE_FRAGMENT: &str = "revocation";

/// On-chain revocation manager using RevocationBitmap2022
pub struct OnChainRevocationManager {
    /// Issuer's DID (owner of the revocation bitmap)
    /// Wrapped in RwLock to allow updating after initialization
    issuer_did: RwLock<String>,
    
    /// The revocation bitmap (roaring bitmap for efficiency)
    bitmap: RwLock<RoaringBitmap>,
    
    /// Next available index for new credentials
    next_index: AtomicU32,
    
    /// Mapping of credential ID to revocation index
    /// Used for looking up which index a credential uses
    credential_to_index: RwLock<HashMap<String, u32>>,
    
    /// Revocation reasons (stored in-memory, not on-chain)
    revocation_reasons: RwLock<HashMap<u32, RevocationInfo>>,
    
    /// Whether the bitmap has been modified since last publish
    dirty: RwLock<bool>,
}

/// Information about a revocation (stored locally, not on-chain)
#[derive(Debug, Clone)]
pub struct RevocationInfo {
    /// The credential ID that was revoked
    pub credential_id: String,
    
    /// When the revocation occurred
    pub revoked_at: DateTime<Utc>,
    
    /// Reason for revocation
    pub reason: Option<String>,
    
    /// Who initiated the revocation
    pub revoked_by: Option<String>,
}

impl OnChainRevocationManager {
    /// Create a new OnChainRevocationManager for an issuer
    ///
    /// # Arguments
    /// * `issuer_did` - The DID of the issuer who owns this revocation bitmap
    pub fn new(issuer_did: String) -> Self {
        info!(issuer_did = %issuer_did, "Initializing On-Chain Revocation Manager");
        
        Self {
            issuer_did: RwLock::new(issuer_did),
            bitmap: RwLock::new(RoaringBitmap::new()),
            next_index: AtomicU32::new(0),
            credential_to_index: RwLock::new(HashMap::new()),
            revocation_reasons: RwLock::new(HashMap::new()),
            dirty: RwLock::new(false),
        }
    }
    
    /// Get the issuer's DID
    pub fn issuer_did(&self) -> String {
        self.issuer_did.read().clone()
    }
    
    /// Update the issuer's DID
    /// 
    /// This should be called after the issuer DID is created on-chain
    /// to update the reference used in credentials.
    pub fn set_issuer_did(&self, new_did: String) {
        info!(old_did = %*self.issuer_did.read(), new_did = %new_did, "Updating issuer DID");
        *self.issuer_did.write() = new_did;
    }
    
    /// Allocate the next available revocation index for a new credential
    ///
    /// # Returns
    /// The index to use in the credential's `credentialStatus.revocationBitmapIndex`
    pub fn allocate_index(&self, credential_id: &str) -> u32 {
        let index = self.next_index.fetch_add(1, Ordering::SeqCst);
        
        // Store the mapping
        let mut mapping = self.credential_to_index.write();
        mapping.insert(credential_id.to_string(), index);
        
        debug!(
            credential_id = %credential_id,
            index = index,
            "Allocated revocation index"
        );
        
        index
    }
    
    /// Create a CredentialStatus for a new credential
    ///
    /// # Arguments
    /// * `credential_id` - The ID of the credential being issued
    ///
    /// # Returns
    /// A CredentialStatus to include in the credential
    pub fn create_credential_status(&self, credential_id: &str) -> CredentialStatus {
        let index = self.allocate_index(credential_id);
        let issuer_did = self.issuer_did.read();
        
        CredentialStatus {
            id: format!("{}#{}", *issuer_did, REVOCATION_SERVICE_FRAGMENT),
            status_type: REVOCATION_SERVICE_TYPE.to_string(),
            revocation_bitmap_index: index.to_string(),
        }
    }
    
    /// Revoke a credential by setting its bit in the bitmap
    ///
    /// # Arguments
    /// * `index` - The revocation bitmap index
    /// * `credential_id` - The credential ID (for tracking)
    /// * `reason` - Optional reason for revocation
    /// * `revoked_by` - Optional identifier of who revoked it
    ///
    /// # Returns
    /// Ok if revoked, Err if already revoked
    pub fn revoke(
        &self,
        index: u32,
        credential_id: &str,
        reason: Option<String>,
        revoked_by: Option<String>,
    ) -> Result<(), OnChainRevocationError> {
        let mut bitmap = self.bitmap.write();
        
        // Check if already revoked
        if bitmap.contains(index) {
            warn!(
                index = index,
                credential_id = %credential_id,
                "Credential already revoked"
            );
            return Err(OnChainRevocationError::AlreadyRevoked {
                index,
                credential_id: credential_id.to_string(),
            });
        }
        
        // Set the bit to 1 (revoked)
        bitmap.insert(index);
        
        // Store revocation info
        let mut reasons = self.revocation_reasons.write();
        reasons.insert(index, RevocationInfo {
            credential_id: credential_id.to_string(),
            revoked_at: Utc::now(),
            reason: reason.clone(),
            revoked_by: revoked_by.clone(),
        });
        
        // Mark as dirty (needs publishing)
        *self.dirty.write() = true;
        
        info!(
            index = index,
            credential_id = %credential_id,
            reason = ?reason,
            "Credential revoked in bitmap"
        );
        
        Ok(())
    }
    
    /// Revoke a credential by its credential ID
    ///
    /// # Arguments
    /// * `credential_id` - The credential ID to revoke
    /// * `reason` - Optional reason for revocation
    /// * `revoked_by` - Optional identifier of who revoked it
    pub fn revoke_by_credential_id(
        &self,
        credential_id: &str,
        reason: Option<String>,
        revoked_by: Option<String>,
    ) -> Result<u32, OnChainRevocationError> {
        let mapping = self.credential_to_index.read();
        
        let index = mapping.get(credential_id)
            .ok_or_else(|| OnChainRevocationError::CredentialNotFound(credential_id.to_string()))?
            .clone();
        
        drop(mapping); // Release read lock before acquiring write lock
        
        self.revoke(index, credential_id, reason, revoked_by)?;
        
        Ok(index)
    }
    
    /// Check if a credential is revoked by its index
    ///
    /// # Arguments
    /// * `index` - The revocation bitmap index to check
    ///
    /// # Returns
    /// true if revoked, false if valid
    pub fn is_revoked(&self, index: u32) -> bool {
        let bitmap = self.bitmap.read();
        bitmap.contains(index)
    }
    
    /// Check if a credential is revoked by its ID
    pub fn is_revoked_by_credential_id(&self, credential_id: &str) -> Option<bool> {
        let mapping = self.credential_to_index.read();
        mapping.get(credential_id).map(|&index| {
            let bitmap = self.bitmap.read();
            bitmap.contains(index)
        })
    }
    
    /// Get revocation info for an index
    pub fn get_revocation_info(&self, index: u32) -> Option<RevocationInfo> {
        let reasons = self.revocation_reasons.read();
        reasons.get(&index).cloned()
    }
    
    /// Encode the bitmap as a data URL for the DID Document service endpoint
    ///
    /// Format: data:application/octet-stream;base64,<zlib-compressed-roaring-bitmap>
    pub fn encode_service_endpoint(&self) -> Result<String, OnChainRevocationError> {
        let bitmap = self.bitmap.read();
        
        // Serialize the roaring bitmap
        let mut serialized = Vec::new();
        bitmap.serialize_into(&mut serialized)
            .map_err(|e| OnChainRevocationError::SerializationError(e.to_string()))?;
        
        // Compress with ZLIB
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&serialized)
            .map_err(|e| OnChainRevocationError::CompressionError(e.to_string()))?;
        let compressed = encoder.finish()
            .map_err(|e| OnChainRevocationError::CompressionError(e.to_string()))?;
        
        // Base64 encode
        let base64_data = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &compressed
        );
        
        // Create data URL
        Ok(format!("data:application/octet-stream;base64,{}", base64_data))
    }
    
    /// Decode a service endpoint data URL into a bitmap
    ///
    /// # Arguments
    /// * `data_url` - The data URL from the DID Document service endpoint
    pub fn decode_service_endpoint(data_url: &str) -> Result<RoaringBitmap, OnChainRevocationError> {
        // Parse data URL
        let prefix = "data:application/octet-stream;base64,";
        if !data_url.starts_with(prefix) {
            return Err(OnChainRevocationError::InvalidDataUrl(
                "Invalid data URL prefix".to_string()
            ));
        }
        
        let base64_data = &data_url[prefix.len()..];
        
        // Base64 decode
        let compressed = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            base64_data
        ).map_err(|e| OnChainRevocationError::DecodingError(e.to_string()))?;
        
        // Decompress with ZLIB
        let mut decoder = ZlibDecoder::new(&compressed[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)
            .map_err(|e| OnChainRevocationError::DecompressionError(e.to_string()))?;
        
        // Deserialize roaring bitmap
        let bitmap = RoaringBitmap::deserialize_from(&decompressed[..])
            .map_err(|e| OnChainRevocationError::DeserializationError(e.to_string()))?;
        
        Ok(bitmap)
    }
    
    /// Check if a credential is revoked by decoding the service endpoint
    ///
    /// # Arguments
    /// * `data_url` - The service endpoint from issuer's DID Document
    /// * `index` - The revocationBitmapIndex from the credential
    pub fn check_revocation_status(
        data_url: &str,
        index: u32,
    ) -> Result<bool, OnChainRevocationError> {
        let bitmap = Self::decode_service_endpoint(data_url)?;
        Ok(bitmap.contains(index))
    }
    
    /// Check if the bitmap needs to be published
    pub fn is_dirty(&self) -> bool {
        *self.dirty.read()
    }
    
    /// Mark the bitmap as published (clean)
    pub fn mark_published(&self) {
        *self.dirty.write() = false;
    }
    
    /// Get statistics about the bitmap
    pub fn stats(&self) -> RevocationBitmapStats {
        let bitmap = self.bitmap.read();
        RevocationBitmapStats {
            total_credentials_issued: self.next_index.load(Ordering::SeqCst),
            revoked_count: bitmap.len() as u32,
            is_dirty: *self.dirty.read(),
            serialized_size_bytes: bitmap.serialized_size(),
        }
    }
    
    /// Load bitmap from an existing service endpoint
    ///
    /// Used when initializing from an existing issuer DID Document
    pub fn load_from_service_endpoint(&self, data_url: &str) -> Result<(), OnChainRevocationError> {
        let loaded_bitmap = Self::decode_service_endpoint(data_url)?;
        
        let mut bitmap = self.bitmap.write();
        *bitmap = loaded_bitmap;
        
        // Update next_index to be after the highest bit
        if let Some(max) = bitmap.max() {
            self.next_index.store(max + 1, Ordering::SeqCst);
        }
        
        info!(
            revoked_count = bitmap.len(),
            "Loaded revocation bitmap from service endpoint"
        );
        
        Ok(())
    }
}

/// Statistics about the revocation bitmap
#[derive(Debug, Clone)]
pub struct RevocationBitmapStats {
    /// Total number of credentials issued (indices allocated)
    pub total_credentials_issued: u32,
    
    /// Number of revoked credentials
    pub revoked_count: u32,
    
    /// Whether the bitmap has unpublished changes
    pub is_dirty: bool,
    
    /// Size of the serialized bitmap in bytes
    pub serialized_size_bytes: usize,
}

/// Errors for on-chain revocation operations
#[derive(Debug, thiserror::Error)]
pub enum OnChainRevocationError {
    #[error("Credential at index {index} (ID: {credential_id}) is already revoked")]
    AlreadyRevoked {
        index: u32,
        credential_id: String,
    },
    
    #[error("Credential not found: {0}")]
    CredentialNotFound(String),
    
    #[error("Invalid data URL: {0}")]
    InvalidDataUrl(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    
    #[error("Compression error: {0}")]
    CompressionError(String),
    
    #[error("Decompression error: {0}")]
    DecompressionError(String),
    
    #[error("Decoding error: {0}")]
    DecodingError(String),
    
    #[error("Publishing error: {0}")]
    PublishingError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_allocate_index() {
        let manager = OnChainRevocationManager::new("did:iota:issuer".to_string());
        
        let idx1 = manager.allocate_index("cred-1");
        let idx2 = manager.allocate_index("cred-2");
        let idx3 = manager.allocate_index("cred-3");
        
        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);
        assert_eq!(idx3, 2);
    }
    
    #[test]
    fn test_revoke_and_check() {
        let manager = OnChainRevocationManager::new("did:iota:issuer".to_string());
        
        let idx = manager.allocate_index("cred-1");
        
        // Not revoked initially
        assert!(!manager.is_revoked(idx));
        
        // Revoke
        manager.revoke(idx, "cred-1", Some("Test".to_string()), None).unwrap();
        
        // Now revoked
        assert!(manager.is_revoked(idx));
        
        // Can't revoke again
        assert!(manager.revoke(idx, "cred-1", None, None).is_err());
    }
    
    #[test]
    fn test_encode_decode_roundtrip() {
        let manager = OnChainRevocationManager::new("did:iota:issuer".to_string());
        
        // Allocate and revoke some credentials
        for i in 0..10 {
            let cred_id = format!("cred-{}", i);
            let idx = manager.allocate_index(&cred_id);
            if i % 3 == 0 {
                manager.revoke(idx, &cred_id, None, None).unwrap();
            }
        }
        
        // Encode
        let data_url = manager.encode_service_endpoint().unwrap();
        
        // Decode
        let decoded_bitmap = OnChainRevocationManager::decode_service_endpoint(&data_url).unwrap();
        
        // Check revocation status matches
        for i in 0..10u32 {
            let expected_revoked = i % 3 == 0;
            assert_eq!(decoded_bitmap.contains(i), expected_revoked);
        }
    }
    
    #[test]
    fn test_check_revocation_status() {
        let manager = OnChainRevocationManager::new("did:iota:issuer".to_string());
        
        let idx = manager.allocate_index("cred-1");
        manager.revoke(idx, "cred-1", None, None).unwrap();
        
        let data_url = manager.encode_service_endpoint().unwrap();
        
        // Check status using static method
        assert!(OnChainRevocationManager::check_revocation_status(&data_url, idx).unwrap());
        assert!(!OnChainRevocationManager::check_revocation_status(&data_url, idx + 1).unwrap());
    }
    
    #[test]
    fn test_create_credential_status() {
        let manager = OnChainRevocationManager::new("did:iota:testnet:0x123".to_string());
        
        let status = manager.create_credential_status("cred-1");
        
        assert_eq!(status.id, "did:iota:testnet:0x123#revocation");
        assert_eq!(status.status_type, "RevocationBitmap2022");
        assert_eq!(status.revocation_bitmap_index, "0");
    }
    
    #[test]
    fn test_empty_bitmap_data_url() {
        // Test vector from IOTA spec: empty bitmap
        let empty_data_url = "data:application/octet-stream;base64,ZUp5ek1tQUFBd0FES0FCcg==";
        
        let bitmap = OnChainRevocationManager::decode_service_endpoint(empty_data_url).unwrap();
        
        // Empty bitmap should have no revoked credentials
        assert_eq!(bitmap.len(), 0);
    }
}