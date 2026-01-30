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
    let subscriber = FmtSubscriber::builder()
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
    let did_manager = DIDManager::new(&config).await?;
    let did_manager = Arc::new(did_manager);

    info!("Initializing Cache Manager...");
    let cache = CacheManager::new(&config.cache);
    let cache = Arc::new(cache);

    info!("Initializing Credential Issuer...");
    let credential_issuer = CredentialIssuer::new(
        Arc::clone(&did_manager),
        config.credential.clone(),
    ).await?;

    // Create application state
    let state = Arc::new(AppState {
        config: config.clone(),
        did_manager: Arc::try_unwrap(did_manager).unwrap_or_else(|arc| (*arc).clone()),
        credential_issuer,
        cache: Arc::try_unwrap(cache).unwrap_or_else(|arc| (*arc).clone()),
    });

    // Create router
    let app = api::create_router(Arc::new(AppState {
        config: config.clone(),
        did_manager: DIDManager::new(&config).await?,
        credential_issuer: CredentialIssuer::new(
            Arc::new(DIDManager::new(&config).await?),
            config.credential.clone(),
        ).await?,
        cache: CacheManager::new(&config.cache),
    }));

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