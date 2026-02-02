//! # Error Types for IOTA Identity IoT System
//!
//! This module defines all error types used throughout the system,
//! providing detailed error information for debugging and logging.

use thiserror::Error;

/// Main error type for the entire system
#[derive(Error, Debug)]
pub enum IdentityError {
    // =========================================================================
    // DID ERRORS
    // =========================================================================
    
    /// Error creating a new DID
    #[error("Failed to create DID: {0}")]
    DIDCreationError(String),

    /// Error resolving a DID from the blockchain
    #[error("Failed to resolve DID '{did}': {reason}")]
    DIDResolutionError { did: String, reason: String },

    /// Invalid DID format
    #[error("Invalid DID format: {0}")]
    InvalidDID(String),

    /// DID not found on the blockchain
    #[error("DID not found: {0}")]
    DIDNotFound(String),

    /// DID has been deactivated
    #[error("DID has been deactivated: {0}")]
    DIDDeactivated(String),

    /// DID is already deactivated
    #[error("DID is already deactivated: {0}")]
    DIDAlreadyDeactivated(String),

    /// Error updating a DID (key rotation or deactivation)
    #[error("Failed to update DID: {0}")]
    DIDUpdateError(String),
    
    /// Unauthorized operation (e.g., trying to update a DID not created by this service)
    #[error("Unauthorized operation: {0}")]
    UnauthorizedOperation(String),

    // =========================================================================
    // CREDENTIAL ERRORS
    // =========================================================================
    
    /// Error issuing a credential
    #[error("Failed to issue credential: {0}")]
    CredentialIssuanceError(String),

    /// Error verifying a credential
    #[error("Credential verification failed: {0}")]
    CredentialVerificationError(String),

    /// Credential has expired
    #[error("Credential has expired at {expiration}")]
    CredentialExpired { expiration: String },

    /// Credential has been revoked
    #[error("Credential '{credential_id}' has been revoked: {reason}")]
    CredentialRevoked { credential_id: String, reason: String },

    /// Revocation error
    #[error("Revocation error: {0}")]
    RevocationError(String),

    /// Invalid credential format
    #[error("Invalid credential format: {0}")]
    InvalidCredential(String),

    /// Credential signature is invalid
    #[error("Invalid credential signature")]
    InvalidSignature,

    // =========================================================================
    // CRYPTOGRAPHY ERRORS
    // =========================================================================
    
    /// Invalid public key format or value
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Invalid private key
    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),

    /// Key generation failed
    #[error("Key generation failed: {0}")]
    KeyGenerationError(String),

    /// Signature creation failed
    #[error("Failed to create signature: {0}")]
    SignatureError(String),

    // =========================================================================
    // NETWORK ERRORS (IOTA REBASED)
    // =========================================================================
    
    /// Failed to connect to IOTA node
    #[error("Failed to connect to IOTA node at '{endpoint}': {reason}")]
    NetworkConnectionError { endpoint: String, reason: String },

    /// Transaction failed on IOTA Rebased
    #[error("Transaction failed: {0}")]
    TransactionError(String),

    /// Insufficient gas for transaction
    #[error("Insufficient gas: required {required}, available {available}")]
    InsufficientGas { required: u64, available: u64 },

    /// Failed to get funds from faucet
    #[error("Faucet request failed: {0}")]
    FaucetError(String),

    /// IOTA Identity Package ID not set
    #[error("IOTA_IDENTITY_PKG_ID environment variable not set")]
    MissingPackageId,

    // =========================================================================
    // STORAGE ERRORS
    // =========================================================================
    
    /// Failed to access Stronghold storage
    #[error("Stronghold storage error: {0}")]
    StrongholdError(String),

    /// Failed to encrypt/decrypt data
    #[error("Encryption error: {0}")]
    EncryptionError(String),

    /// Failed to read/write file
    #[error("Storage I/O error: {0}")]
    StorageIOError(String),

    // =========================================================================
    // CACHE ERRORS
    // =========================================================================
    
    /// Cache miss (item not found in cache)
    #[error("Cache miss for key: {0}")]
    CacheMiss(String),

    /// Cache error
    #[error("Cache error: {0}")]
    CacheError(String),

    // =========================================================================
    // TLS ERRORS
    // =========================================================================
    
    /// TLS handshake failed
    #[error("TLS handshake failed: {0}")]
    TLSHandshakeError(String),

    /// TLS certificate error
    #[error("TLS certificate error: {0}")]
    TLSCertificateError(String),

    /// DID authentication failed after TLS handshake
    #[error("DID authentication failed: {0}")]
    DIDAuthenticationError(String),

    /// Connection timeout
    #[error("Connection timeout after {timeout_secs} seconds")]
    ConnectionTimeout { timeout_secs: u64 },

    // =========================================================================
    // API ERRORS
    // =========================================================================
    
    /// Invalid request format
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// Device registration failed
    #[error("Device registration failed: {0}")]
    RegistrationError(String),

    /// Unauthorized access
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    // =========================================================================
    // CONFIGURATION ERRORS
    // =========================================================================
    
    /// Invalid configuration
    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    /// Missing required environment variable
    #[error("Missing environment variable: {0}")]
    MissingEnvVar(String),

    // =========================================================================
    // GENERIC ERRORS
    // =========================================================================
    
    /// Internal error
    #[error("Internal error: {0}")]
    InternalError(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Operation not supported
    #[error("Operation not supported: {0}")]
    NotSupported(String),
}

/// Result type alias using IdentityError
pub type IdentityResult<T> = Result<T, IdentityError>;

// =============================================================================
// ERROR CONVERSIONS
// =============================================================================

impl From<serde_json::Error> for IdentityError {
    fn from(err: serde_json::Error) -> Self {
        IdentityError::SerializationError(err.to_string())
    }
}

impl From<std::io::Error> for IdentityError {
    fn from(err: std::io::Error) -> Self {
        IdentityError::StorageIOError(err.to_string())
    }
}

impl From<hex::FromHexError> for IdentityError {
    fn from(err: hex::FromHexError) -> Self {
        IdentityError::InvalidPublicKey(err.to_string())
    }
}

impl From<base64::DecodeError> for IdentityError {
    fn from(err: base64::DecodeError) -> Self {
        IdentityError::SerializationError(err.to_string())
    }
}

impl From<ed25519_dalek::SignatureError> for IdentityError {
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        IdentityError::SignatureError(err.to_string())
    }
}

// =============================================================================
// ERROR CATEGORIES (for metrics and logging)
// =============================================================================

impl IdentityError {
    /// Get the error category for metrics/logging
    pub fn category(&self) -> &'static str {
        match self {
            IdentityError::DIDCreationError(_)
            | IdentityError::DIDResolutionError { .. }
            | IdentityError::InvalidDID(_)
            | IdentityError::DIDNotFound(_)
            | IdentityError::DIDDeactivated(_)
            | IdentityError::DIDAlreadyDeactivated(_)
            | IdentityError::DIDUpdateError(_) => "did",

            IdentityError::CredentialIssuanceError(_)
            | IdentityError::CredentialVerificationError(_)
            | IdentityError::CredentialExpired { .. }
            | IdentityError::CredentialRevoked { .. }
            | IdentityError::RevocationError(_)
            | IdentityError::InvalidCredential(_)
            | IdentityError::InvalidSignature => "credential",

            IdentityError::InvalidPublicKey(_)
            | IdentityError::InvalidPrivateKey(_)
            | IdentityError::KeyGenerationError(_)
            | IdentityError::SignatureError(_) => "crypto",

            IdentityError::NetworkConnectionError { .. }
            | IdentityError::TransactionError(_)
            | IdentityError::InsufficientGas { .. }
            | IdentityError::FaucetError(_)
            | IdentityError::MissingPackageId => "network",

            IdentityError::StrongholdError(_)
            | IdentityError::EncryptionError(_)
            | IdentityError::StorageIOError(_) => "storage",

            IdentityError::CacheMiss(_)
            | IdentityError::CacheError(_) => "cache",

            IdentityError::TLSHandshakeError(_)
            | IdentityError::TLSCertificateError(_)
            | IdentityError::DIDAuthenticationError(_)
            | IdentityError::ConnectionTimeout { .. } => "tls",

            IdentityError::InvalidRequest(_)
            | IdentityError::RegistrationError(_)
            | IdentityError::Unauthorized(_)
            | IdentityError::UnauthorizedOperation(_) => "api",

            IdentityError::ConfigurationError(_)
            | IdentityError::MissingEnvVar(_) => "config",

            IdentityError::InternalError(_)
            | IdentityError::SerializationError(_)
            | IdentityError::NotSupported(_) => "internal",
        }
    }

    /// Check if the error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            IdentityError::NetworkConnectionError { .. }
                | IdentityError::TransactionError(_)
                | IdentityError::FaucetError(_)
                | IdentityError::ConnectionTimeout { .. }
                | IdentityError::CacheError(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_category() {
        let err = IdentityError::DIDNotFound("did:iota:test".into());
        assert_eq!(err.category(), "did");

        let err = IdentityError::InvalidSignature;
        assert_eq!(err.category(), "credential");

        let err = IdentityError::TLSHandshakeError("test".into());
        assert_eq!(err.category(), "tls");
    }

    #[test]
    fn test_is_retryable() {
        let err = IdentityError::NetworkConnectionError {
            endpoint: "test".into(),
            reason: "timeout".into(),
        };
        assert!(err.is_retryable());

        let err = IdentityError::InvalidDID("bad did".into());
        assert!(!err.is_retryable());
    }
}