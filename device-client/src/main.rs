//! # IOTA Device Client CLI
//!
//! Command-line tool for device operations:
//! - Register device with Identity Service
//! - Show device identity
//! - Test TLS connection with DID authentication
//!
//! ## Usage
//!
//! ```bash
//! # Register a new device
//! device-client register --type sensor --capabilities temperature,humidity
//!
//! # Show device identity
//! device-client show
//!
//! # Connect to another device
//! device-client connect --addr 192.168.1.100:8443
//!
//! # Start as server
//! device-client server --port 8443
//! ```

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::sync::Arc;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use device_client::{DeviceRegistrar, DIDResolver, TlsClient, TlsServer};
use shared::{
    config::DeviceClientConfig,
    types::DeviceType,
};

#[derive(Parser)]
#[command(name = "device-client")]
#[command(about = "IOTA IoT Device Client with DID Authentication")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Identity Service URL
    #[arg(long, default_value = "http://localhost:8080")]
    identity_service: String,

    /// IOTA network (testnet, devnet, mainnet, local)
    #[arg(long, default_value = "testnet")]
    network: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Register this device with the Identity Service
    Register {
        /// Device type (sensor, gateway, actuator, controller, edge, generic)
        #[arg(long, short = 't', default_value = "generic")]
        device_type: String,

        /// Device capabilities (comma-separated)
        #[arg(long, short = 'c', default_value = "")]
        capabilities: String,
    },

    /// Show device identity information
    Show,

    /// Connect to another device using TLS with DID authentication
    Connect {
        /// Address to connect to (host:port)
        #[arg(long, short = 'a')]
        addr: String,
    },

    /// Start as a TLS server accepting connections
    Server {
        /// Port to listen on
        #[arg(long, short = 'p', default_value = "8443")]
        port: u16,
    },

    /// Resolve a DID from the blockchain
    Resolve {
        /// DID to resolve
        #[arg(long, short = 'd')]
        did: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .init();

    let cli = Cli::parse();

    // Build config
    let mut config = DeviceClientConfig::default();
    config.identity_service_url = cli.identity_service;
    config.network = shared::config::IotaNetwork::from_str(&cli.network);

    match cli.command {
        Commands::Register { device_type, capabilities } => {
            register_device(&config, &device_type, &capabilities).await?;
        }
        Commands::Show => {
            show_identity(&config).await?;
        }
        Commands::Connect { addr } => {
            connect_to_device(&config, &addr).await?;
        }
        Commands::Server { port } => {
            start_server(&config, port).await?;
        }
        Commands::Resolve { did } => {
            resolve_did(&config, &did).await?;
        }
    }

    Ok(())
}

async fn register_device(config: &DeviceClientConfig, device_type: &str, capabilities: &str) -> Result<()> {
    info!("Registering device...");

    let device_type = match device_type.to_lowercase().as_str() {
        "sensor" => DeviceType::Sensor,
        "gateway" => DeviceType::Gateway,
        "actuator" => DeviceType::Actuator,
        "controller" => DeviceType::Controller,
        "edge" => DeviceType::Edge,
        _ => DeviceType::Generic,
    };

    let capabilities: Vec<String> = capabilities
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.trim().to_string())
        .collect();

    let mut registrar = DeviceRegistrar::new(config).await?;
    
    if registrar.is_registered() {
        println!("Device already registered!");
        println!("DID: {}", registrar.did().unwrap_or("unknown"));
        println!("\nUse 're-register' to register with a new identity.");
        return Ok(());
    }

    let response = registrar.register(device_type, capabilities).await?;

    println!("\n✓ Device registered successfully!");
    println!("  DID: {}", response.did);
    println!("  Object ID: {}", response.object_id);
    println!("  Credential expires: {}", response.credential_expires_at);

    Ok(())
}

async fn show_identity(config: &DeviceClientConfig) -> Result<()> {
    let storage = device_client::SecureStorage::new(&config.storage).await?;

    if let Some(identity) = storage.load_identity().await? {
        println!("\nDevice Identity:");
        println!("  DID: {}", identity.did);
        println!("  Object ID: {}", identity.object_id);
        println!("  Type: {:?}", identity.device_type);
        println!("  Capabilities: {:?}", identity.capabilities);
        println!("  Created: {}", identity.created_at);
        println!("  Status: {:?}", identity.status);

        if let Some(jwt) = storage.load_credential_jwt().await? {
            println!("\nCredential JWT stored: {} chars", jwt.len());
        }
    } else {
        println!("\nNo device identity found.");
        println!("Run 'device-client register' to register this device.");
    }

    Ok(())
}

async fn connect_to_device(config: &DeviceClientConfig, addr: &str) -> Result<()> {
    info!(addr = %addr, "Connecting to device");

    let storage = device_client::SecureStorage::new(&config.storage).await?;
    
    let identity = storage.load_identity().await?
        .ok_or_else(|| anyhow::anyhow!("Device not registered"))?;
    
    let credential_jwt = storage.load_credential_jwt().await?
        .ok_or_else(|| anyhow::anyhow!("No credential stored"))?;

    let resolver = Arc::new(DIDResolver::new(config).await?);
    
    let client = TlsClient::new(
        resolver,
        identity.did.clone(),
        credential_jwt,
        config.tls.clone(),
    )?;

    let connection = client.connect(addr).await?;

    println!("\n✓ Connected and authenticated!");
    println!("  Peer DID: {}", connection.peer_did);

    // Keep connection open briefly to demonstrate
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    Ok(())
}

async fn start_server(config: &DeviceClientConfig, port: u16) -> Result<()> {
    info!(port = port, "Starting TLS server");

    let storage = device_client::SecureStorage::new(&config.storage).await?;
    
    let identity = storage.load_identity().await?
        .ok_or_else(|| anyhow::anyhow!("Device not registered"))?;
    
    let credential_jwt = storage.load_credential_jwt().await?
        .ok_or_else(|| anyhow::anyhow!("No credential stored"))?;

    let resolver = Arc::new(DIDResolver::new(config).await?);
    
    let server = TlsServer::new(
        resolver,
        identity.did.clone(),
        credential_jwt,
        config.tls.clone(),
    )?;

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    println!("\n✓ Server listening on port {}", port);
    println!("  DID: {}", identity.did);

    loop {
        let (stream, addr) = listener.accept().await?;
        info!(peer = %addr, "New connection");

        match server.accept(stream).await {
            Ok(connection) => {
                println!("  Authenticated client: {}", connection.peer_did);
            }
            Err(e) => {
                println!("  Authentication failed: {}", e);
            }
        }
    }
}

async fn resolve_did(config: &DeviceClientConfig, did: &str) -> Result<()> {
    info!(did = %did, "Resolving DID");

    let resolver = DIDResolver::new(config).await?;
    
    let start = std::time::Instant::now();
    let document = resolver.resolve(did).await?;
    let elapsed = start.elapsed();

    println!("\nDID Document:");
    println!("{}", serde_json::to_string_pretty(&*document)?);
    println!("\nResolved in {:?}", elapsed);
    println!("Cached: {}", resolver.is_cached(did).await);

    Ok(())
}