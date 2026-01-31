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
//! - `GET /metrics` - Get service metrics

use anyhow::Result;
use std::sync::Arc;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use identity_service::{
    api, cache::CacheManager, credential::CredentialIssuer, did::DIDManager, AppState,
};
use shared::config::IdentityServiceConfig;

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

    // Initialize components
    info!("Initializing DID Manager...");
    let did_manager = Arc::new(DIDManager::new(&config).await?);

    info!("Initializing Cache Manager...");
    let cache = Arc::new(CacheManager::new(&config.cache));

    info!("Initializing Credential Issuer...");
    let credential_issuer = CredentialIssuer::new(
        Arc::clone(&did_manager),
        config.credential.clone(),
    ).await?;

    // Create application state (using Arc for non-Clone types)
    let state = Arc::new(AppState {
        config: config.clone(),
        did_manager: Arc::clone(&did_manager),
        credential_issuer,
        cache: Arc::clone(&cache),
    });

    // Create router with shared state
    let app = api::create_router(state);

    // Start server
    let bind_addr = config.api.bind_addr();
    info!(address = %bind_addr, "Starting HTTP server");

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    
    info!("Server running at http://{}", bind_addr);
    info!("API documentation:");
    info!("  POST /api/v1/device/register - Register a new device");
    info!("  GET  /api/v1/did/resolve/:did - Resolve a DID");
    info!("  POST /api/v1/credential/verify - Verify a credential");

    axum::serve(listener, app).await?;

    Ok(())
}