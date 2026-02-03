//! # IOTA Identity Service
//!
//! Backend service for IoT device identity management using IOTA Rebased.
//!
//! ## Running
//!
//! ```bash
//! # Set required environment variables
//! export IOTA_IDENTITY_PKG_ID=0x222741bbdff74b42df48a7b4733185e9b24becb8ccfbafe8eac864ab4e4cc555
//! export STRONGHOLD_PASSWORD=your_secure_password
//! export IOTA_NETWORK=testnet
//!
//! # Run the service
//! cargo run --release
//! ```
//!
//! ## API Endpoints
//!
//! - `GET /health` - Health check
//! - `POST /api/v1/device/register` - Register a new device
//! - `GET /api/v1/did/resolve/:did` - Resolve a DID
//! - `POST /api/v1/credential/verify` - Verify a credential
//! - `POST /api/v1/credential/revoke` - Revoke a credential (on-chain)
//! - `GET /metrics` - Get service metrics

use anyhow::Result;
use std::sync::Arc;
use std::path::PathBuf;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use identity_service::{
    api, cache::CacheManager, credential::CredentialIssuer, did::DIDManager, 
    revocation::{RevocationManager, OnChainRevocationManager}, AppState,
};
use shared::config::IdentityServiceConfig;

/// Default path for storing issuer identity
const ISSUER_STORAGE_DIR: &str = ".iota-identity-service";

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(true)
        .with_thread_ids(true)
        .init();

    info!("Starting IOTA Identity Service");
    info!("Version: {}", shared::VERSION);

    // Load configuration
    let config = IdentityServiceConfig::from_env()?;
    config.validate()?;

    info!(
        network = %config.network,
        endpoint = %config.endpoint(),
        "Configuration loaded"
    );

    // Determine storage path for issuer identity
    let storage_path = dirs::home_dir()
        .map(|home| home.join(ISSUER_STORAGE_DIR))
        .unwrap_or_else(|| PathBuf::from(ISSUER_STORAGE_DIR));
    
    info!(path = ?storage_path, "Issuer identity storage path");

    // Initialize components
    info!("Initializing DID Manager...");
    let did_manager = Arc::new(DIDManager::new(&config).await?);

    info!("Initializing Cache Manager...");
    let cache = Arc::new(CacheManager::new(&config.cache));

    info!("Initializing In-Memory Revocation Manager...");
    let revocation_manager = Arc::new(RevocationManager::new());

    // Initialize On-Chain Revocation Manager (RevocationBitmap2022)
    // Using placeholder issuer DID - will be updated when issuer is initialized
    let issuer_did = format!("did:iota:{}:issuer", config.network);
    info!(issuer_did = %issuer_did, "Initializing On-Chain Revocation Manager (RevocationBitmap2022)...");
    let onchain_revocation_manager = Arc::new(OnChainRevocationManager::new(issuer_did));

    info!("Initializing Credential Issuer with RevocationBitmap2022...");
    let credential_issuer = CredentialIssuer::new(
        Arc::clone(&did_manager),
        Arc::clone(&onchain_revocation_manager),
        config.credential.clone(),
        Some(storage_path.clone()),
    ).await?;
    
    // Check if issuer was loaded from storage
    let current_issuer = credential_issuer.issuer_did();
    if current_issuer != "did:iota:issuer" && !current_issuer.ends_with(":issuer") {
        info!(issuer_did = %current_issuer, "Issuer identity loaded from storage - ready to issue credentials");
    } else {
        info!("No existing issuer identity found. Call POST /api/v1/issuer/initialize to create one.");
    }

    // Create application state (using Arc for non-Clone types)
    let state = Arc::new(AppState {
        config: config.clone(),
        did_manager: Arc::clone(&did_manager),
        credential_issuer,
        cache: Arc::clone(&cache),
        revocation_manager: Arc::clone(&revocation_manager),
        onchain_revocation_manager: Arc::clone(&onchain_revocation_manager),
    });

    // Create router with shared state
    let app = api::create_router(state);

    // Start server
    let bind_addr = config.api.bind_addr();
    info!(address = %bind_addr, "Starting HTTP server");

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    
    info!("Server running at http://{}", bind_addr);
    info!("API documentation:");
    info!("  POST /api/v1/issuer/initialize - Initialize issuer DID (required first!)");
    info!("  POST /api/v1/device/register - Register a new device");
    info!("  GET  /api/v1/did/resolve/:did - Resolve a DID");
    info!("  POST /api/v1/credential/verify - Verify a credential");
    info!("  POST /api/v1/credential/revoke-onchain - Revoke a credential (RevocationBitmap2022)");

    axum::serve(listener, app).await?;

    Ok(())
}