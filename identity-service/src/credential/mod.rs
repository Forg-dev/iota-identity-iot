//! # Credential Issuer for W3C Verifiable Credentials
//!
//! This module handles:
//! - Issuing Verifiable Credentials for IoT devices
//! - Verifying credential signatures
//! - Credential revocation using RevocationBitmap2022
//!
//! ## W3C VC Data Model
//!
//! Credentials follow the W3C Verifiable Credentials Data Model:
//! - Context: https://www.w3.org/2018/credentials/v1
//! - Types: VerifiableCredential, IoTDeviceCredential
//! - Proof: Ed25519Signature2020
//! - Status: RevocationBitmap2022

use chrono::{Duration, Utc};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use std::sync::Arc;
use tracing::{debug, info};

use shared::{
    config::CredentialConfig,
    constants::*,
    error::{IdentityError, IdentityResult},
    types::*,
};

use crate::did::DIDManager;
use crate::revocation::{OnChainRevocationManager, REVOCATION_SERVICE_TYPE};

/// Credential Issuer for generating W3C Verifiable Credentials
pub struct CredentialIssuer {
    /// DID Manager for resolving DIDs
    did_manager: Arc<DIDManager>,
    
    /// On-chain revocation manager
    revocation_manager: Arc<OnChainRevocationManager>,
    
    /// Issuer's signing key
    signing_key: SigningKey,
    
    /// Issuer's DID (will be set after initialization)
    issuer_did: String,
    
    /// Configuration
    config: CredentialConfig,
}

impl CredentialIssuer {
    /// Create a new CredentialIssuer
    ///
    /// # Arguments
    /// * `did_manager` - DID Manager for resolving DIDs
    /// * `revocation_manager` - On-chain revocation manager for RevocationBitmap2022
    /// * `config` - Credential configuration
    pub async fn new(
        did_manager: Arc<DIDManager>,
        revocation_manager: Arc<OnChainRevocationManager>,
        config: CredentialConfig,
    ) -> IdentityResult<Self> {
        info!(
            issuer_name = %config.issuer_name,
            validity_days = config.validity_secs / 86400,
            "Initializing Credential Issuer with RevocationBitmap2022"
        );

        // Generate a new signing key for the issuer
        let signing_key = SigningKey::generate(&mut rand::thread_rng());

        // For now, use a placeholder DID
        // In production, this would come from did_manager.get_or_create_issuer_did()
        let issuer_did = "did:iota:issuer".to_string();

        Ok(Self {
            did_manager,
            revocation_manager,
            signing_key,
            issuer_did,
            config,
        })
    }

    /// Issue a Verifiable Credential for a device
    ///
    /// # Arguments
    /// * `subject_did` - The device's DID
    /// * `device_type` - Type of device
    /// * `capabilities` - Device capabilities
    /// * `metadata` - Optional additional metadata
    ///
    /// # Returns
    /// A DeviceCredential with proof (signature) and credentialStatus for revocation
    pub async fn issue_credential(
        &self,
        subject_did: &str,
        device_type: DeviceType,
        capabilities: Vec<String>,
        metadata: Option<CredentialMetadata>,
    ) -> IdentityResult<DeviceCredential> {
        info!(
            subject_did = %subject_did,
            device_type = ?device_type,
            "Issuing credential for device with RevocationBitmap2022"
        );

        let now = Utc::now();
        let expiration = now + Duration::seconds(self.config.validity_secs as i64);

        // Create credential ID
        let credential_id = format!(
            "urn:uuid:{}",
            uuid::Uuid::new_v4()
        );

        // Build credential subject
        let subject = CredentialSubject {
            id: subject_did.to_string(),
            device_type,
            capabilities,
            manufacturer: metadata.as_ref().and_then(|m| m.manufacturer.clone()),
            model: metadata.as_ref().and_then(|m| m.model.clone()),
            firmware_version: metadata.as_ref().and_then(|m| m.firmware_version.clone()),
        };

        // Create credential status for RevocationBitmap2022
        let credential_status = self.revocation_manager.create_credential_status(&credential_id);
        
        debug!(
            credential_id = %credential_id,
            revocation_index = %credential_status.revocation_bitmap_index,
            "Allocated revocation index for credential"
        );

        // Create the credential (without proof first)
        let mut credential = DeviceCredential {
            id: credential_id.clone(),
            context: vec![
                CREDENTIAL_CONTEXT_VC.to_string(),
                "https://w3id.org/security/suites/ed25519-2020/v1".to_string(),
            ],
            credential_type: vec![
                "VerifiableCredential".to_string(),
                CREDENTIAL_TYPE_IOT_DEVICE.to_string(),
            ],
            issuer: self.issuer_did.clone(),
            issuance_date: now,
            expiration_date: expiration,
            credential_subject: subject,
            credential_status: Some(credential_status),
            proof: None,
        };

        // Sign the credential
        let proof = self.create_proof(&credential)?;
        credential.proof = Some(proof);

        info!(
            credential_id = %credential_id,
            expires_at = %expiration,
            "Credential issued successfully with revocation support"
        );

        Ok(credential)
    }

    /// Create a proof (signature) for a credential
    fn create_proof(&self, credential: &DeviceCredential) -> IdentityResult<CredentialProof> {
        // Serialize credential without proof for signing
        let credential_without_proof = DeviceCredential {
            proof: None,
            ..credential.clone()
        };

        let canonical = serde_json::to_string(&credential_without_proof)
            .map_err(|e| IdentityError::SerializationError(e.to_string()))?;

        // Sign the canonical form
        let signature = self.signing_key.sign(canonical.as_bytes());
        let signature_base64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            signature.to_bytes()
        );

        Ok(CredentialProof {
            proof_type: "Ed25519Signature2020".to_string(),
            created: Utc::now(),
            verification_method: format!("{}#key-1", self.issuer_did),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: signature_base64,
        })
    }

    /// Verify a credential's signature and revocation status
    ///
    /// # Arguments
    /// * `credential` - The credential to verify
    ///
    /// # Returns
    /// Ok(()) if valid, Err if invalid or revoked
    pub async fn verify_credential(&self, credential: &DeviceCredential) -> IdentityResult<()> {
        debug!(
            credential_id = %credential.id,
            "Verifying credential"
        );

        // Check expiration
        if credential.is_expired() {
            return Err(IdentityError::CredentialExpired {
                expiration: credential.expiration_date.to_rfc3339(),
            });
        }

        // Check on-chain revocation status if credentialStatus is present
        if let Some(status) = &credential.credential_status {
            if status.status_type == REVOCATION_SERVICE_TYPE {
                let index: u32 = status.revocation_bitmap_index.parse()
                    .map_err(|_| IdentityError::InvalidCredential(
                        "Invalid revocationBitmapIndex".into()
                    ))?;
                
                // Check if revoked in our local bitmap
                if self.revocation_manager.is_revoked(index) {
                    let info = self.revocation_manager.get_revocation_info(index);
                    let reason = info.and_then(|i| i.reason).unwrap_or_else(|| "No reason provided".to_string());
                    
                    return Err(IdentityError::CredentialRevoked {
                        credential_id: credential.id.clone(),
                        reason,
                    });
                }
            }
        }

        // Get the proof
        let proof = credential.proof.as_ref()
            .ok_or_else(|| IdentityError::InvalidCredential("Missing proof".into()))?;

        // Resolve the issuer's DID to get the public key
        // In production, this would query the blockchain
        // For now, we'll use our own public key if it's our credential
        let issuer_public_key = if credential.issuer == self.issuer_did {
            self.signing_key.verifying_key()
        } else {
            // Would resolve from blockchain
            return Err(IdentityError::CredentialVerificationError(
                "Cannot verify credentials from other issuers yet".into()
            ));
        };

        // Verify the signature
        self.verify_signature(credential, &issuer_public_key, proof)?;

        info!(credential_id = %credential.id, "Credential verified successfully");

        Ok(())
    }

    /// Verify a credential's signature against a public key
    fn verify_signature(
        &self,
        credential: &DeviceCredential,
        public_key: &VerifyingKey,
        proof: &CredentialProof,
    ) -> IdentityResult<()> {
        // Recreate the canonical form (without proof)
        let credential_without_proof = DeviceCredential {
            proof: None,
            ..credential.clone()
        };

        let canonical = serde_json::to_string(&credential_without_proof)
            .map_err(|e| IdentityError::SerializationError(e.to_string()))?;

        // Decode the signature
        let signature_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &proof.proof_value
        ).map_err(|e| IdentityError::InvalidCredential(
            format!("Invalid signature encoding: {}", e)
        ))?;

        let signature = ed25519_dalek::Signature::from_slice(&signature_bytes)
            .map_err(|_e| IdentityError::InvalidSignature)?;

        // Verify
        public_key.verify_strict(canonical.as_bytes(), &signature)
            .map_err(|_| IdentityError::InvalidSignature)?;

        Ok(())
    }

    /// Issue a credential as JWT (compact format)
    pub async fn issue_credential_jwt(
        &self,
        subject_did: &str,
        device_type: DeviceType,
        capabilities: Vec<String>,
        metadata: Option<CredentialMetadata>,
    ) -> IdentityResult<String> {
        // Issue the credential
        let credential = self.issue_credential(
            subject_did,
            device_type,
            capabilities,
            metadata,
        ).await?;

        // Convert to JWT format
        // Header
        let header = serde_json::json!({
            "alg": "EdDSA",
            "typ": "JWT"
        });

        // Payload (the credential)
        let payload = serde_json::json!({
            "vc": credential,
            "iss": self.issuer_did,
            "sub": subject_did,
            "iat": credential.issuance_date.timestamp(),
            "exp": credential.expiration_date.timestamp()
        });

        // Encode header and payload
        let header_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            serde_json::to_string(&header)?
        );
        let payload_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            serde_json::to_string(&payload)?
        );

        // Sign
        let message = format!("{}.{}", header_b64, payload_b64);
        let signature = self.signing_key.sign(message.as_bytes());
        let signature_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            signature.to_bytes()
        );

        Ok(format!("{}.{}.{}", header_b64, payload_b64, signature_b64))
    }

    /// Get the issuer's DID
    pub fn issuer_did(&self) -> &str {
        &self.issuer_did
    }

    /// Get the issuer's public key
    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
    
    /// Get the on-chain revocation manager
    pub fn revocation_manager(&self) -> &Arc<OnChainRevocationManager> {
        &self.revocation_manager
    }
    
    /// Revoke a credential on-chain
    ///
    /// # Arguments
    /// * `credential_id` - The credential ID to revoke
    /// * `reason` - Optional reason for revocation
    ///
    /// # Returns
    /// The revocation index if successful
    pub fn revoke_credential(
        &self,
        credential_id: &str,
        reason: Option<String>,
    ) -> Result<u32, IdentityError> {
        self.revocation_manager
            .revoke_by_credential_id(credential_id, reason, Some("issuer".to_string()))
            .map_err(|e| IdentityError::RevocationError(e.to_string()))
    }
    
    /// Check if a credential is revoked
    pub fn is_credential_revoked(&self, credential_id: &str) -> Option<bool> {
        self.revocation_manager.is_revoked_by_credential_id(credential_id)
    }
    
    /// Get the revocation bitmap service endpoint for the issuer's DID Document
    pub fn get_revocation_service_endpoint(&self) -> Result<String, IdentityError> {
        self.revocation_manager
            .encode_service_endpoint()
            .map_err(|e| IdentityError::RevocationError(e.to_string()))
    }
}

/// Optional metadata for credentials
#[derive(Debug, Clone, Default)]
pub struct CredentialMetadata {
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub firmware_version: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests would need a mock DIDManager
    // For now, they serve as documentation of the API

    #[test]
    fn test_signing_key_generation() {
        let key = SigningKey::generate(&mut rand::thread_rng());
        let public_key = key.verifying_key();
        
        // Sign and verify
        let message = b"test message";
        let signature = key.sign(message);
        assert!(public_key.verify_strict(message, &signature).is_ok());
    }
}