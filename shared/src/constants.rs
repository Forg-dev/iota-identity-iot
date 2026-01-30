//! # Constants for IOTA Identity IoT System
//!
//! This module contains all constants used throughout the system,
//! specifically configured for IOTA Rebased networks.

// =============================================================================
// IOTA REBASED NETWORK ENDPOINTS
// =============================================================================

/// IOTA Rebased Testnet RPC endpoint
pub const IOTA_TESTNET_ENDPOINT: &str = "https://api.testnet.iota.cafe";

/// IOTA Rebased Devnet RPC endpoint  
pub const IOTA_DEVNET_ENDPOINT: &str = "https://api.devnet.iota.cafe";

/// IOTA Rebased Mainnet RPC endpoint
pub const IOTA_MAINNET_ENDPOINT: &str = "https://api.mainnet.iota.cafe";

/// Local IOTA node endpoint (for development)
pub const IOTA_LOCAL_ENDPOINT: &str = "http://127.0.0.1:9000";

// =============================================================================
// IOTA REBASED IDENTITY PACKAGE IDs
// These are the deployed Move packages for Identity operations
// =============================================================================

/// Identity Package ID for IOTA Rebased Testnet
/// This is REQUIRED for all identity operations on testnet
pub const IOTA_IDENTITY_PKG_ID_TESTNET: &str = 
    "0x222741bbdff74b42df48a7b4733185e9b24becb8ccfbafe8eac864ab4e4cc555";

/// Identity Package ID for IOTA Rebased Devnet
/// Note: This may change with redeployments
pub const IOTA_IDENTITY_PKG_ID_DEVNET: &str = 
    "0x222741bbdff74b42df48a7b4733185e9b24becb8ccfbafe8eac864ab4e4cc555";

// =============================================================================
// IOTA REBASED FAUCET ENDPOINTS (for testnet/devnet)
// =============================================================================

/// Faucet endpoint for testnet
pub const IOTA_FAUCET_TESTNET: &str = "https://faucet.testnet.iota.cafe/gas";

/// Faucet endpoint for devnet
pub const IOTA_FAUCET_DEVNET: &str = "https://faucet.devnet.iota.cafe/gas";

// =============================================================================
// GAS BUDGETS (IOTA Rebased requires gas for transactions)
// =============================================================================

/// Default gas budget for publishing a new DID Document
pub const GAS_BUDGET_PUBLISH_DID: u64 = 50_000_000;

/// Gas budget for updating a DID Document
pub const GAS_BUDGET_UPDATE_DID: u64 = 30_000_000;

/// Gas budget for deactivating a DID
pub const GAS_BUDGET_DEACTIVATE_DID: u64 = 20_000_000;

/// Gas budget for revoking credentials
pub const GAS_BUDGET_REVOKE_CREDENTIAL: u64 = 25_000_000;

// =============================================================================
// CACHE CONFIGURATION
// =============================================================================

/// Time-to-live for cached DID Documents (24 hours)
pub const CACHE_TTL_DID_DOCUMENT_SECS: u64 = 24 * 60 * 60;

/// Time-to-live for cached Verifiable Credentials (12 hours)
pub const CACHE_TTL_CREDENTIAL_SECS: u64 = 12 * 60 * 60;

/// Time-to-live for cached resolution results (1 hour)
pub const CACHE_TTL_RESOLUTION_SECS: u64 = 60 * 60;

/// Maximum number of DID Documents to cache
pub const CACHE_MAX_DID_DOCUMENTS: u64 = 100_000;

/// Maximum number of credentials to cache
pub const CACHE_MAX_CREDENTIALS: u64 = 500_000;

// =============================================================================
// CREDENTIAL CONFIGURATION
// =============================================================================

/// Default credential validity period (365 days in seconds)
pub const CREDENTIAL_VALIDITY_SECS: u64 = 365 * 24 * 60 * 60;

/// Credential type for IoT devices
pub const CREDENTIAL_TYPE_IOT_DEVICE: &str = "IoTDeviceCredential";

/// Credential context (W3C Verifiable Credentials)
pub const CREDENTIAL_CONTEXT_VC: &str = "https://www.w3.org/2018/credentials/v1";

// =============================================================================
// TLS CONFIGURATION
// =============================================================================

/// Self-signed certificate validity (90 days)
pub const TLS_CERT_VALIDITY_DAYS: u32 = 90;

/// TLS handshake timeout (seconds)
pub const TLS_HANDSHAKE_TIMEOUT_SECS: u64 = 30;

/// DID authentication timeout after TLS handshake (seconds)
pub const DID_AUTH_TIMEOUT_SECS: u64 = 60;

// =============================================================================
// API CONFIGURATION
// =============================================================================

/// Default Identity Service API port
pub const IDENTITY_SERVICE_PORT: u16 = 8080;

/// API version prefix
pub const API_VERSION: &str = "v1";

/// Maximum request body size (1 MB)
pub const MAX_REQUEST_BODY_SIZE: usize = 1024 * 1024;

// =============================================================================
// BENCHMARK CONFIGURATION
// =============================================================================

/// Number of devices for small-scale test
pub const BENCHMARK_DEVICES_SMALL: usize = 100;

/// Number of devices for medium-scale test
pub const BENCHMARK_DEVICES_MEDIUM: usize = 1_000;

/// Number of devices for large-scale test
pub const BENCHMARK_DEVICES_LARGE: usize = 10_000;

/// Number of devices for full-scale test
pub const BENCHMARK_DEVICES_FULL: usize = 100_000;

// =============================================================================
// STORAGE PATHS
// =============================================================================

/// Default path for Stronghold secure storage
pub const DEFAULT_STRONGHOLD_PATH: &str = "./stronghold";

/// Default path for device storage
pub const DEFAULT_DEVICE_STORAGE_PATH: &str = "./device_storage";

// =============================================================================
// DID METHOD
// =============================================================================

/// DID method for IOTA
pub const DID_METHOD_IOTA: &str = "iota";

/// DID prefix
pub const DID_PREFIX: &str = "did:iota:";

// =============================================================================
// VERIFICATION METHOD TYPES
// =============================================================================

/// Ed25519 verification key type (W3C standard)
pub const VERIFICATION_KEY_TYPE_ED25519: &str = "Ed25519VerificationKey2020";

/// JSON Web Key type
pub const JWK_KEY_TYPE_ED25519: &str = "Ed25519";

// =============================================================================
// ENVIRONMENT VARIABLE NAMES
// =============================================================================

/// Environment variable for IOTA Identity Package ID
pub const ENV_IOTA_IDENTITY_PKG_ID: &str = "IOTA_IDENTITY_PKG_ID";

/// Environment variable for IOTA RPC endpoint
pub const ENV_IOTA_RPC_ENDPOINT: &str = "IOTA_RPC_ENDPOINT";

/// Environment variable for IOTA network name
pub const ENV_IOTA_NETWORK: &str = "IOTA_NETWORK";

/// Environment variable for Stronghold password
pub const ENV_STRONGHOLD_PASSWORD: &str = "STRONGHOLD_PASSWORD";

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Get the appropriate endpoint for a network name
pub fn get_endpoint_for_network(network: &str) -> &'static str {
    match network.to_lowercase().as_str() {
        "testnet" => IOTA_TESTNET_ENDPOINT,
        "devnet" => IOTA_DEVNET_ENDPOINT,
        "mainnet" => IOTA_MAINNET_ENDPOINT,
        "local" | "localhost" => IOTA_LOCAL_ENDPOINT,
        _ => IOTA_TESTNET_ENDPOINT, // Default to testnet
    }
}

/// Get the appropriate faucet URL for a network
pub fn get_faucet_for_network(network: &str) -> Option<&'static str> {
    match network.to_lowercase().as_str() {
        "testnet" => Some(IOTA_FAUCET_TESTNET),
        "devnet" => Some(IOTA_FAUCET_DEVNET),
        _ => None, // No faucet for mainnet or local
    }
}

/// Get the Identity Package ID for a network
pub fn get_identity_pkg_id_for_network(network: &str) -> &'static str {
    match network.to_lowercase().as_str() {
        "testnet" => IOTA_IDENTITY_PKG_ID_TESTNET,
        "devnet" => IOTA_IDENTITY_PKG_ID_DEVNET,
        // For mainnet and local, user must provide via environment variable
        _ => IOTA_IDENTITY_PKG_ID_TESTNET,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_endpoint_for_network() {
        assert_eq!(get_endpoint_for_network("testnet"), IOTA_TESTNET_ENDPOINT);
        assert_eq!(get_endpoint_for_network("TESTNET"), IOTA_TESTNET_ENDPOINT);
        assert_eq!(get_endpoint_for_network("devnet"), IOTA_DEVNET_ENDPOINT);
        assert_eq!(get_endpoint_for_network("mainnet"), IOTA_MAINNET_ENDPOINT);
        assert_eq!(get_endpoint_for_network("local"), IOTA_LOCAL_ENDPOINT);
        assert_eq!(get_endpoint_for_network("unknown"), IOTA_TESTNET_ENDPOINT);
    }

    #[test]
    fn test_get_faucet_for_network() {
        assert!(get_faucet_for_network("testnet").is_some());
        assert!(get_faucet_for_network("devnet").is_some());
        assert!(get_faucet_for_network("mainnet").is_none());
    }
}