//! # Configuration for IOTA Identity IoT System
//!
//! This module handles configuration loading and validation,
//! supporting both environment variables and configuration files.

use crate::constants::*;
use crate::error::{IdentityError, IdentityResult};
use serde::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;

// =============================================================================
// NETWORK CONFIGURATION
// =============================================================================

/// IOTA network to connect to
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum IotaNetwork {
    /// IOTA Rebased Testnet
    #[default]
    Testnet,
    /// IOTA Rebased Devnet
    Devnet,
    /// IOTA Rebased Mainnet
    Mainnet,
    /// Local development node
    Local,
}

impl IotaNetwork {
    /// Get the RPC endpoint for this network
    pub fn endpoint(&self) -> &'static str {
        match self {
            IotaNetwork::Testnet => IOTA_TESTNET_ENDPOINT,
            IotaNetwork::Devnet => IOTA_DEVNET_ENDPOINT,
            IotaNetwork::Mainnet => IOTA_MAINNET_ENDPOINT,
            IotaNetwork::Local => IOTA_LOCAL_ENDPOINT,
        }
    }

    /// Get the faucet URL for this network (if available)
    pub fn faucet_url(&self) -> Option<&'static str> {
        match self {
            IotaNetwork::Testnet => Some(IOTA_FAUCET_TESTNET),
            IotaNetwork::Devnet => Some(IOTA_FAUCET_DEVNET),
            IotaNetwork::Local => Some(IOTA_FAUCET_LOCAL),
            IotaNetwork::Mainnet => None,
        }
    }

    /// Get the Identity Package ID for this network
    pub fn identity_package_id(&self) -> &'static str {
        match self {
            IotaNetwork::Testnet => IOTA_IDENTITY_PKG_ID_TESTNET,
            IotaNetwork::Devnet => IOTA_IDENTITY_PKG_ID_DEVNET,
            // For mainnet/local, should be provided via env var
            _ => IOTA_IDENTITY_PKG_ID_TESTNET,
        }
    }

    /// Check if this network has a faucet
    pub fn has_faucet(&self) -> bool {
        matches!(self, IotaNetwork::Testnet | IotaNetwork::Devnet | IotaNetwork::Local)
    }

    /// Parse network from string
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "testnet" => IotaNetwork::Testnet,
            "devnet" => IotaNetwork::Devnet,
            "mainnet" => IotaNetwork::Mainnet,
            "local" | "localnet" | "localhost" => IotaNetwork::Local,
            _ => IotaNetwork::Testnet,
        }
    }
}

impl std::fmt::Display for IotaNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IotaNetwork::Testnet => write!(f, "testnet"),
            IotaNetwork::Devnet => write!(f, "devnet"),
            IotaNetwork::Mainnet => write!(f, "mainnet"),
            IotaNetwork::Local => write!(f, "local"),
        }
    }
}

// =============================================================================
// IDENTITY SERVICE CONFIGURATION
// =============================================================================

/// Configuration for the Identity Service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityServiceConfig {
    /// IOTA network to use
    pub network: IotaNetwork,

    /// Custom RPC endpoint (overrides network default)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_endpoint: Option<String>,

    /// Identity Package ID (required for IOTA Rebased)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_package_id: Option<String>,

    /// API server configuration
    pub api: ApiConfig,

    /// Cache configuration
    pub cache: CacheConfig,

    /// Stronghold storage configuration
    pub storage: StorageConfig,

    /// Credential configuration
    pub credential: CredentialConfig,
}

impl Default for IdentityServiceConfig {
    fn default() -> Self {
        Self {
            network: IotaNetwork::default(),
            custom_endpoint: None,
            identity_package_id: None,
            api: ApiConfig::default(),
            cache: CacheConfig::default(),
            storage: StorageConfig::default(),
            credential: CredentialConfig::default(),
        }
    }
}

impl IdentityServiceConfig {
    /// Get the effective RPC endpoint
    pub fn endpoint(&self) -> &str {
        self.custom_endpoint
            .as_deref()
            .unwrap_or_else(|| self.network.endpoint())
    }

    /// Get the effective Identity Package ID
    pub fn package_id(&self) -> IdentityResult<&str> {
        if let Some(ref pkg_id) = self.identity_package_id {
            return Ok(pkg_id);
        }

        // Try environment variable
        if let Ok(pkg_id) = env::var(ENV_IOTA_IDENTITY_PKG_ID) {
            // Note: This leaks memory, but it's a one-time operation
            return Ok(Box::leak(pkg_id.into_boxed_str()));
        }

        // Use network default
        Ok(self.network.identity_package_id())
    }

    /// Load configuration from environment variables
    pub fn from_env() -> IdentityResult<Self> {
        let mut config = Self::default();

        // Network
        if let Ok(network) = env::var(ENV_IOTA_NETWORK) {
            config.network = IotaNetwork::from_str(&network);
        }

        // Custom endpoint
        if let Ok(endpoint) = env::var(ENV_IOTA_RPC_ENDPOINT) {
            config.custom_endpoint = Some(endpoint);
        }

        // Package ID
        if let Ok(pkg_id) = env::var(ENV_IOTA_IDENTITY_PKG_ID) {
            config.identity_package_id = Some(pkg_id);
        }

        // Stronghold password (required)
        if let Ok(password) = env::var(ENV_STRONGHOLD_PASSWORD) {
            config.storage.stronghold_password = Some(password);
        }

        Ok(config)
    }

    /// Validate the configuration
    pub fn validate(&self) -> IdentityResult<()> {
        // Check that we have a way to get the package ID
        let _ = self.package_id()?;

        // Validate storage config
        self.storage.validate()?;

        Ok(())
    }
}

// =============================================================================
// API CONFIGURATION
// =============================================================================

/// API server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Host to bind to
    pub host: String,

    /// Port to listen on
    pub port: u16,

    /// Enable CORS
    pub enable_cors: bool,

    /// Maximum request body size in bytes
    pub max_body_size: usize,

    /// Request timeout in seconds
    pub request_timeout_secs: u64,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".into(),
            port: IDENTITY_SERVICE_PORT,
            enable_cors: true,
            max_body_size: MAX_REQUEST_BODY_SIZE,
            request_timeout_secs: 30,
        }
    }
}

impl ApiConfig {
    /// Get the bind address
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

// =============================================================================
// CACHE CONFIGURATION
// =============================================================================

/// Cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Enable caching
    pub enabled: bool,

    /// DID Document cache TTL in seconds
    pub did_ttl_secs: u64,

    /// Credential cache TTL in seconds
    pub credential_ttl_secs: u64,

    /// Maximum number of cached DID Documents
    pub max_did_documents: u64,

    /// Maximum number of cached credentials
    pub max_credentials: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            did_ttl_secs: CACHE_TTL_DID_DOCUMENT_SECS,
            credential_ttl_secs: CACHE_TTL_CREDENTIAL_SECS,
            max_did_documents: CACHE_MAX_DID_DOCUMENTS,
            max_credentials: CACHE_MAX_CREDENTIALS,
        }
    }
}

// =============================================================================
// STORAGE CONFIGURATION
// =============================================================================

/// Storage configuration for Stronghold
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Path to Stronghold file
    pub stronghold_path: PathBuf,

    /// Stronghold password (should come from env var in production)
    #[serde(skip_serializing)]
    pub stronghold_password: Option<String>,

    /// Path for device data storage
    pub data_path: PathBuf,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            stronghold_path: PathBuf::from(DEFAULT_STRONGHOLD_PATH).join("issuer.stronghold"),
            stronghold_password: None,
            data_path: PathBuf::from("./data"),
        }
    }
}

impl StorageConfig {
    /// Validate storage configuration
    pub fn validate(&self) -> IdentityResult<()> {
        // Note: Stronghold password is currently not used since we use in-memory storage.
        // This validation is kept for future Stronghold integration but is not enforced.
        Ok(())
    }

    /// Get the Stronghold password (if set)
    pub fn get_password(&self) -> IdentityResult<String> {
        if let Some(ref password) = self.stronghold_password {
            return Ok(password.clone());
        }

        env::var(ENV_STRONGHOLD_PASSWORD)
            .map_err(|_| IdentityError::MissingEnvVar(ENV_STRONGHOLD_PASSWORD.into()))
    }
}

// =============================================================================
// CREDENTIAL CONFIGURATION
// =============================================================================

/// Credential configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialConfig {
    /// Credential validity period in seconds
    pub validity_secs: u64,

    /// Issuer name
    pub issuer_name: String,
}

impl Default for CredentialConfig {
    fn default() -> Self {
        Self {
            validity_secs: CREDENTIAL_VALIDITY_SECS,
            issuer_name: "IOTA IoT Identity Service".into(),
        }
    }
}

// =============================================================================
// DEVICE CLIENT CONFIGURATION
// =============================================================================

/// Configuration for the Device Client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceClientConfig {
    /// IOTA network to use
    pub network: IotaNetwork,

    /// Custom RPC endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_endpoint: Option<String>,

    /// Identity Service URL (for registration)
    pub identity_service_url: String,

    /// Local storage configuration
    pub storage: StorageConfig,

    /// Cache configuration
    pub cache: CacheConfig,

    /// TLS configuration
    pub tls: TlsConfig,
}

impl Default for DeviceClientConfig {
    fn default() -> Self {
        Self {
            network: IotaNetwork::default(),
            custom_endpoint: None,
            identity_service_url: format!("http://localhost:{}", IDENTITY_SERVICE_PORT),
            storage: StorageConfig {
                stronghold_path: PathBuf::from(DEFAULT_DEVICE_STORAGE_PATH).join("device.stronghold"),
                stronghold_password: None,
                data_path: PathBuf::from(DEFAULT_DEVICE_STORAGE_PATH),
            },
            cache: CacheConfig::default(),
            tls: TlsConfig::default(),
        }
    }
}

// =============================================================================
// TLS CONFIGURATION
// =============================================================================

/// TLS configuration for device communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Certificate validity in days
    pub cert_validity_days: u32,

    /// TLS handshake timeout in seconds
    pub handshake_timeout_secs: u64,

    /// DID authentication timeout in seconds
    pub did_auth_timeout_secs: u64,

    /// Path to store generated certificates
    pub cert_path: PathBuf,
    
    /// Whether to verify credential revocation status during TLS auth
    pub verify_revocation: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert_validity_days: TLS_CERT_VALIDITY_DAYS,
            handshake_timeout_secs: TLS_HANDSHAKE_TIMEOUT_SECS,
            did_auth_timeout_secs: DID_AUTH_TIMEOUT_SECS,
            cert_path: PathBuf::from("./certs"),
            verify_revocation: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_endpoint() {
        assert_eq!(IotaNetwork::Testnet.endpoint(), IOTA_TESTNET_ENDPOINT);
        assert_eq!(IotaNetwork::Devnet.endpoint(), IOTA_DEVNET_ENDPOINT);
    }

    #[test]
    fn test_network_from_str() {
        assert_eq!(IotaNetwork::from_str("testnet"), IotaNetwork::Testnet);
        assert_eq!(IotaNetwork::from_str("TESTNET"), IotaNetwork::Testnet);
        assert_eq!(IotaNetwork::from_str("devnet"), IotaNetwork::Devnet);
        assert_eq!(IotaNetwork::from_str("unknown"), IotaNetwork::Testnet);
    }

    #[test]
    fn test_config_defaults() {
        let config = IdentityServiceConfig::default();
        assert_eq!(config.network, IotaNetwork::Testnet);
        assert!(config.cache.enabled);
    }

    #[test]
    fn test_api_bind_addr() {
        let config = ApiConfig::default();
        assert_eq!(config.bind_addr(), "0.0.0.0:8080");
    }
}