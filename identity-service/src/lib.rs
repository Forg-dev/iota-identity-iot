//! # Identity Service for IOTA Rebased IoT Authentication
//!
//! This service provides:
//! - DID creation and management on IOTA Rebased
//! - Verifiable Credential issuance (W3C VC)
//! - Credential revocation management (in-memory + on-chain RevocationBitmap2022)
//! - Key rotation support
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
//!
//! ## Revocation
//!
//! Two revocation mechanisms are available:
//! 1. In-memory revocation (RevocationManager) - fast but not persistent
//! 2. On-chain revocation (OnChainRevocationManager) - uses RevocationBitmap2022

pub mod api;
pub mod cache;
pub mod credential;
pub mod did;
pub mod revocation;

use shared::config::IdentityServiceConfig;

/// Application state shared across handlers
pub struct AppState {
    /// Configuration
    pub config: IdentityServiceConfig,
    /// DID Manager for IOTA Rebased operations (wrapped in Arc - not Clone)
    pub did_manager: std::sync::Arc<did::DIDManager>,
    /// Credential Issuer
    pub credential_issuer: credential::CredentialIssuer,
    /// Cache layer (wrapped in Arc - not Clone)
    pub cache: std::sync::Arc<cache::CacheManager>,
    /// In-memory Revocation Manager for credential revocation
    pub revocation_manager: std::sync::Arc<revocation::RevocationManager>,
    /// On-chain Revocation Manager using RevocationBitmap2022
    pub onchain_revocation_manager: std::sync::Arc<revocation::OnChainRevocationManager>,
}