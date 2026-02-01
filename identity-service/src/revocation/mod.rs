//! # Revocation Manager
//!
//! Manages credential revocation status.
//! 
//! ## Architecture
//!
//! For simplicity, this implementation uses an in-memory revocation list.
//! In production, this should be:
//! - Stored on-chain using IOTA Rebased (RevocationBitmap2022)
//! - Or in a persistent database with blockchain anchoring
//!
//! ## W3C Revocation Standards
//!
//! This follows the W3C Verifiable Credentials Status List approach:
//! - Each credential has a unique ID
//! - Revocation status is tracked separately from the credential
//! - Revocation can include timestamp and reason

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Revocation entry for a credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    /// Credential ID
    pub credential_id: String,
    
    /// When the credential was revoked
    pub revoked_at: DateTime<Utc>,
    
    /// Reason for revocation
    pub reason: Option<String>,
    
    /// Who initiated the revocation (admin, issuer, device owner)
    pub revoked_by: Option<String>,
}

/// Manages credential revocation status
pub struct RevocationManager {
    /// In-memory revocation list
    /// Key: credential_id, Value: RevocationEntry
    revocations: RwLock<HashMap<String, RevocationEntry>>,
    
    /// Statistics
    total_revocations: std::sync::atomic::AtomicU64,
}

impl RevocationManager {
    /// Create a new RevocationManager
    pub fn new() -> Self {
        info!("Initializing Revocation Manager");
        Self {
            revocations: RwLock::new(HashMap::new()),
            total_revocations: std::sync::atomic::AtomicU64::new(0),
        }
    }
    
    /// Revoke a credential
    ///
    /// # Arguments
    /// * `credential_id` - The unique ID of the credential to revoke
    /// * `reason` - Optional reason for revocation
    /// * `revoked_by` - Optional identifier of who revoked it
    ///
    /// # Returns
    /// The revocation entry if successful, error if already revoked
    pub fn revoke(
        &self,
        credential_id: &str,
        reason: Option<String>,
        revoked_by: Option<String>,
    ) -> Result<RevocationEntry, RevocationError> {
        let mut revocations = self.revocations.write();
        
        // Check if already revoked
        if revocations.contains_key(credential_id) {
            warn!(credential_id = %credential_id, "Credential already revoked");
            return Err(RevocationError::AlreadyRevoked(credential_id.to_string()));
        }
        
        let entry = RevocationEntry {
            credential_id: credential_id.to_string(),
            revoked_at: Utc::now(),
            reason,
            revoked_by,
        };
        
        revocations.insert(credential_id.to_string(), entry.clone());
        self.total_revocations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        
        info!(
            credential_id = %credential_id,
            revoked_at = %entry.revoked_at,
            "Credential revoked"
        );
        
        Ok(entry)
    }
    
    /// Check if a credential is revoked
    ///
    /// # Arguments
    /// * `credential_id` - The credential ID to check
    ///
    /// # Returns
    /// Some(RevocationEntry) if revoked, None if valid
    pub fn is_revoked(&self, credential_id: &str) -> Option<RevocationEntry> {
        let revocations = self.revocations.read();
        let result = revocations.get(credential_id).cloned();
        
        if result.is_some() {
            debug!(credential_id = %credential_id, "Credential is revoked");
        }
        
        result
    }
    
    /// Get revocation status for a credential
    ///
    /// # Arguments
    /// * `credential_id` - The credential ID to check
    ///
    /// # Returns
    /// (is_revoked, optional_entry)
    pub fn get_status(&self, credential_id: &str) -> (bool, Option<RevocationEntry>) {
        let entry = self.is_revoked(credential_id);
        (entry.is_some(), entry)
    }
    
    /// Unrevoke a credential (for administrative purposes)
    ///
    /// Note: In production, this should be a privileged operation
    /// and may not be allowed depending on the use case
    pub fn unrevoke(&self, credential_id: &str) -> Result<(), RevocationError> {
        let mut revocations = self.revocations.write();
        
        if revocations.remove(credential_id).is_some() {
            info!(credential_id = %credential_id, "Credential un-revoked");
            Ok(())
        } else {
            Err(RevocationError::NotRevoked(credential_id.to_string()))
        }
    }
    
    /// Get all revoked credentials
    pub fn list_revoked(&self) -> Vec<RevocationEntry> {
        let revocations = self.revocations.read();
        revocations.values().cloned().collect()
    }
    
    /// Get total number of revocations
    pub fn total_revocations(&self) -> u64 {
        self.total_revocations.load(std::sync::atomic::Ordering::Relaxed)
    }
    
    /// Get current number of revoked credentials
    pub fn current_revoked_count(&self) -> usize {
        self.revocations.read().len()
    }
}

impl Default for RevocationManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors related to revocation operations
#[derive(Debug, thiserror::Error)]
pub enum RevocationError {
    #[error("Credential '{0}' is already revoked")]
    AlreadyRevoked(String),
    
    #[error("Credential '{0}' is not revoked")]
    NotRevoked(String),
    
    #[error("Invalid credential ID: {0}")]
    InvalidCredentialId(String),
    
    #[error("Revocation failed: {0}")]
    RevocationFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_revoke_credential() {
        let manager = RevocationManager::new();
        let cred_id = "cred-123";
        
        // Initially not revoked
        assert!(manager.is_revoked(cred_id).is_none());
        
        // Revoke
        let entry = manager.revoke(cred_id, Some("Test reason".into()), None).unwrap();
        assert_eq!(entry.credential_id, cred_id);
        assert_eq!(entry.reason, Some("Test reason".to_string()));
        
        // Now revoked
        assert!(manager.is_revoked(cred_id).is_some());
        
        // Can't revoke again
        assert!(manager.revoke(cred_id, None, None).is_err());
    }
    
    #[test]
    fn test_unrevoke_credential() {
        let manager = RevocationManager::new();
        let cred_id = "cred-456";
        
        // Revoke first
        manager.revoke(cred_id, None, None).unwrap();
        assert!(manager.is_revoked(cred_id).is_some());
        
        // Unrevoke
        manager.unrevoke(cred_id).unwrap();
        assert!(manager.is_revoked(cred_id).is_none());
    }
    
    #[test]
    fn test_statistics() {
        let manager = RevocationManager::new();
        
        manager.revoke("cred-1", None, None).unwrap();
        manager.revoke("cred-2", None, None).unwrap();
        
        assert_eq!(manager.total_revocations(), 2);
        assert_eq!(manager.current_revoked_count(), 2);
        
        manager.unrevoke("cred-1").unwrap();
        
        // Total still 2 (historical), current is 1
        assert_eq!(manager.total_revocations(), 2);
        assert_eq!(manager.current_revoked_count(), 1);
    }
}