//! # Identity Service for IOTA Rebased IoT Authentication
//!
//! This service provides:
//! - DID creation and management on IOTA Rebased
//! - Verifiable Credential issuance (W3C VC)
//! - REST API for device registration
//! - Multi-level caching for performance
//!
//! ## IOTA Rebased Architecture
//!
//! This service uses IOTA Rebased APIs which are fundamentally different
//! from the older Stardust version:
//!
//! - Uses `IdentityClient` instead of `IotaIdentityClient`
//! - Transactions require gas (IOTA tokens)
//! - Identity objects are stored as Move objects on-chain
//! - Package ID is required for all operations

pub mod api;
pub mod cache;
pub mod credential;
pub mod did;

use shared::config::IdentityServiceConfig;

/// Application state shared across handlers
pub struct AppState {
    /// Configuration
    pub config: IdentityServiceConfig,
    /// DID Manager for IOTA Rebased operations
    pub did_manager: did::DIDManager,
    /// Credential Issuer
    pub credential_issuer: credential::CredentialIssuer,
    /// Cache layer
    pub cache: cache::CacheManager,
}