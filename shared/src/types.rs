//! # Shared Data Types for IOTA Identity IoT System
//!
//! This module defines all shared data structures used across
//! the Identity Service and Device Client components.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// =============================================================================
// DEVICE IDENTITY
// =============================================================================

/// Represents a device's identity in the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdentity {
    /// Unique identifier for this device record
    pub id: Uuid,
    
    /// The DID string (e.g., "did:iota:0x...")
    pub did: String,
    
    /// Object ID on IOTA Rebased (the identity object)
    pub object_id: String,
    
    /// Device's public key in hex format (Ed25519, 64 hex chars)
    pub public_key_hex: String,
    
    /// Type of device (e.g., "sensor", "gateway", "actuator")
    pub device_type: DeviceType,
    
    /// Device capabilities
    pub capabilities: Vec<String>,
    
    /// Timestamp when the DID was created
    pub created_at: DateTime<Utc>,
    
    /// Timestamp of last update
    pub updated_at: DateTime<Utc>,
    
    /// Current status of the device identity
    pub status: DeviceStatus,
}

impl DeviceIdentity {
    /// Create a new DeviceIdentity
    pub fn new(
        did: String,
        object_id: String,
        public_key_hex: String,
        device_type: DeviceType,
        capabilities: Vec<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            did,
            object_id,
            public_key_hex,
            device_type,
            capabilities,
            created_at: now,
            updated_at: now,
            status: DeviceStatus::Active,
        }
    }
}

/// Type of IoT device
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceType {
    /// Sensor device (temperature, humidity, etc.)
    Sensor,
    /// Gateway device
    Gateway,
    /// Actuator device
    Actuator,
    /// Controller device
    Controller,
    /// Edge computing device
    Edge,
    /// Generic IoT device
    Generic,
}

impl Default for DeviceType {
    fn default() -> Self {
        DeviceType::Generic
    }
}

/// Status of a device identity
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    /// Device is active and can authenticate
    Active,
    /// Device is suspended (temporary)
    Suspended,
    /// Device identity has been revoked
    Revoked,
    /// Device is pending verification
    Pending,
}

impl Default for DeviceStatus {
    fn default() -> Self {
        DeviceStatus::Active
    }
}

// =============================================================================
// VERIFIABLE CREDENTIAL
// =============================================================================

/// Represents a W3C Verifiable Credential for IoT devices
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCredential {
    /// Unique credential identifier
    pub id: String,
    
    /// W3C VC context
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    
    /// Credential types
    #[serde(rename = "type")]
    pub credential_type: Vec<String>,
    
    /// Issuer DID
    pub issuer: String,
    
    /// Issuance date
    #[serde(rename = "issuanceDate")]
    pub issuance_date: DateTime<Utc>,
    
    /// Expiration date
    #[serde(rename = "expirationDate")]
    pub expiration_date: DateTime<Utc>,
    
    /// Credential subject (the device)
    #[serde(rename = "credentialSubject")]
    pub credential_subject: CredentialSubject,
    
    /// Proof (signature)
    pub proof: Option<CredentialProof>,
}

/// Subject of a credential (the device being credentialed)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSubject {
    /// Subject DID (device DID)
    pub id: String,
    
    /// Device type
    #[serde(rename = "deviceType")]
    pub device_type: DeviceType,
    
    /// Device capabilities
    pub capabilities: Vec<String>,
    
    /// Manufacturer (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manufacturer: Option<String>,
    
    /// Model (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    
    /// Firmware version (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "firmwareVersion")]
    pub firmware_version: Option<String>,
}

/// Proof (signature) for a credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialProof {
    /// Proof type (e.g., "Ed25519Signature2020")
    #[serde(rename = "type")]
    pub proof_type: String,
    
    /// When the proof was created
    pub created: DateTime<Utc>,
    
    /// Verification method (key ID in issuer's DID Document)
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    
    /// Purpose of the proof
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    
    /// The actual signature value (base64 encoded)
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

// =============================================================================
// DID DOCUMENT (simplified representation)
// =============================================================================

/// Simplified DID Document representation for caching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimplifiedDIDDocument {
    /// The DID
    pub id: String,
    
    /// Verification methods (public keys)
    #[serde(rename = "verificationMethod")]
    pub verification_methods: Vec<VerificationMethod>,
    
    /// Authentication methods
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Vec<String>>,
    
    /// Services (endpoints)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<Vec<Service>>,
    
    /// When the document was last updated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<DateTime<Utc>>,
}

/// Verification method in a DID Document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    /// Method ID (e.g., "did:iota:0x...#key-1")
    pub id: String,
    
    /// Controller DID
    pub controller: String,
    
    /// Key type (e.g., "Ed25519VerificationKey2020")
    #[serde(rename = "type")]
    pub key_type: String,
    
    /// Public key in multibase format
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

/// Service endpoint in a DID Document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    /// Service ID
    pub id: String,
    
    /// Service type
    #[serde(rename = "type")]
    pub service_type: String,
    
    /// Service endpoint URL
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

// =============================================================================
// API REQUEST/RESPONSE TYPES
// =============================================================================

/// Request to register a new device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRegistrationRequest {
    /// Device's public key (Ed25519, hex encoded)
    pub public_key: String,
    
    /// Type of device
    pub device_type: DeviceType,
    
    /// Device capabilities
    #[serde(default)]
    pub capabilities: Vec<String>,
    
    /// Optional manufacturer info
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manufacturer: Option<String>,
    
    /// Optional model info
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

/// Response from device registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRegistrationResponse {
    /// Assigned DID
    pub did: String,
    
    /// Object ID on IOTA Rebased
    pub object_id: String,
    
    /// Issued credential (JWT format)
    pub credential_jwt: String,
    
    /// Credential expiration
    pub credential_expires_at: DateTime<Utc>,
}

/// Request to verify a credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialVerificationRequest {
    /// Credential in JWT format
    pub credential_jwt: String,
}

/// Response from credential verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialVerificationResponse {
    /// Whether the credential is valid
    pub valid: bool,
    
    /// Subject DID (if valid)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_did: Option<String>,
    
    /// Issuer DID (if valid)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_did: Option<String>,
    
    /// Error message (if invalid)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    
    /// Expiration date
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Request to resolve a DID
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDResolutionRequest {
    /// DID to resolve
    pub did: String,
    
    /// Whether to bypass cache
    #[serde(default)]
    pub bypass_cache: bool,
}

/// Response from DID resolution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDResolutionResponse {
    /// The resolved DID Document
    pub did_document: SimplifiedDIDDocument,
    
    /// Whether this came from cache
    pub from_cache: bool,
    
    /// Resolution time in milliseconds
    pub resolution_time_ms: u64,
}

// =============================================================================
// TLS AUTHENTICATION MESSAGES
// =============================================================================

/// Message sent during DID authentication (post-TLS handshake)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDAuthMessage {
    /// Message type
    #[serde(rename = "type")]
    pub message_type: DIDAuthMessageType,
    
    /// Sender's DID
    pub did: String,
    
    /// Sender's credential (JWT)
    pub credential_jwt: String,
    
    /// Challenge response (if responding to challenge)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_response: Option<String>,
    
    /// New challenge for the other party
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Type of DID authentication message
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DIDAuthMessageType {
    /// Initial hello with DID and credential
    Hello,
    /// Challenge for the other party
    Challenge,
    /// Response to a challenge
    Response,
    /// Authentication successful
    Success,
    /// Authentication failed
    Failure,
}

// =============================================================================
// METRICS & BENCHMARKING
// =============================================================================

/// Performance metrics for a single operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationMetrics {
    /// Type of operation
    pub operation: String,
    
    /// Duration in microseconds
    pub duration_us: u64,
    
    /// Whether the operation succeeded
    pub success: bool,
    
    /// Whether cache was used
    pub cache_hit: bool,
    
    /// Additional metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Aggregated metrics for benchmarking
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AggregatedMetrics {
    /// Total number of operations
    pub total_operations: u64,
    
    /// Number of successful operations
    pub successful_operations: u64,
    
    /// Number of failed operations
    pub failed_operations: u64,
    
    /// Mean latency in microseconds
    pub mean_latency_us: f64,
    
    /// Median latency in microseconds
    pub median_latency_us: f64,
    
    /// 95th percentile latency
    pub p95_latency_us: f64,
    
    /// 99th percentile latency
    pub p99_latency_us: f64,
    
    /// Minimum latency
    pub min_latency_us: u64,
    
    /// Maximum latency
    pub max_latency_us: u64,
    
    /// Cache hit rate (0.0 to 1.0)
    pub cache_hit_rate: f64,
    
    /// Throughput (operations per second)
    pub throughput_ops: f64,
}

// =============================================================================
// UTILITY IMPLEMENTATIONS
// =============================================================================

impl DeviceCredential {
    /// Check if the credential has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expiration_date
    }
    
    /// Get time until expiration
    pub fn time_until_expiration(&self) -> chrono::Duration {
        self.expiration_date - Utc::now()
    }
}

impl SimplifiedDIDDocument {
    /// Get the primary verification method
    pub fn primary_verification_method(&self) -> Option<&VerificationMethod> {
        self.verification_methods.first()
    }
    
    /// Find a verification method by ID
    pub fn find_verification_method(&self, id: &str) -> Option<&VerificationMethod> {
        self.verification_methods.iter().find(|vm| vm.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_identity_creation() {
        let identity = DeviceIdentity::new(
            "did:iota:0x123".into(),
            "0x123".into(),
            "a".repeat(64),
            DeviceType::Sensor,
            vec!["temperature".into(), "humidity".into()],
        );
        
        assert_eq!(identity.did, "did:iota:0x123");
        assert_eq!(identity.device_type, DeviceType::Sensor);
        assert_eq!(identity.status, DeviceStatus::Active);
    }

    #[test]
    fn test_credential_expiration() {
        let cred = DeviceCredential {
            id: "test".into(),
            context: vec![],
            credential_type: vec![],
            issuer: "did:iota:issuer".into(),
            issuance_date: Utc::now(),
            expiration_date: Utc::now() - chrono::Duration::hours(1),
            credential_subject: CredentialSubject {
                id: "did:iota:device".into(),
                device_type: DeviceType::Sensor,
                capabilities: vec![],
                manufacturer: None,
                model: None,
                firmware_version: None,
            },
            proof: None,
        };
        
        assert!(cred.is_expired());
    }
}