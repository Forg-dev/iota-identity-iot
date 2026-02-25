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

use device_client::{DeviceRegistrar, DIDResolver, IdentityManager, TlsClient, TlsServer};
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

    /// Data storage directory
    #[arg(long, default_value = "./device-data")]
    data_dir: String,
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

    /// Re-register this device (creates new identity)
    Reregister {
        /// Device type (sensor, gateway, actuator, controller, edge, generic)
        #[arg(long, short = 't', default_value = "generic")]
        device_type: String,

        /// Device capabilities (comma-separated)
        #[arg(long, short = 'c', default_value = "")]
        capabilities: String,
    },

    /// Show device identity information
    Show,

    /// Sign a message with the device's private key
    Sign {
        /// Message to sign
        #[arg(long, short = 'm')]
        message: String,
    },

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

    /// Clear all stored device data
    Clear,
    RotateKey,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .init();

    let cli = Cli::parse();

    // Build config
    let mut config = DeviceClientConfig::default();
    config.identity_service_url = cli.identity_service;
    config.network = shared::config::IotaNetwork::from_str(&cli.network);
    config.storage.data_path = std::path::PathBuf::from(&cli.data_dir);

    match cli.command {
        Commands::Register { device_type, capabilities } => {
            register_device(&config, &device_type, &capabilities, false).await?;
        }
        Commands::Reregister { device_type, capabilities } => {
            register_device(&config, &device_type, &capabilities, true).await?;
        }
        Commands::Show => {
            show_identity(&config).await?;
        }
        Commands::Sign { message } => {
            sign_message(&config, &message).await?;
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
        Commands::Clear => {
            clear_storage(&config).await?;
        }
        Commands::RotateKey => {
            rotate_key(&config).await?;
        }
    }

    Ok(())
}

fn parse_device_type(s: &str) -> DeviceType {
    match s.to_lowercase().as_str() {
        "sensor" => DeviceType::Sensor,
        "gateway" => DeviceType::Gateway,
        "actuator" => DeviceType::Actuator,
        "controller" => DeviceType::Controller,
        "edge" => DeviceType::Edge,
        _ => DeviceType::Generic,
    }
}

fn parse_capabilities(s: &str) -> Vec<String> {
    s.split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.trim().to_string())
        .collect()
}

async fn register_device(
    config: &DeviceClientConfig, 
    device_type: &str, 
    capabilities: &str,
    force: bool,
) -> Result<()> {
    info!("Registering device...");

    let device_type = parse_device_type(device_type);
    let capabilities = parse_capabilities(capabilities);

    let mut registrar = DeviceRegistrar::new(config).await?;
    
    if registrar.is_registered() && !force {
        println!("Device already registered!");
        println!("DID: {}", registrar.did().unwrap_or("unknown"));
        println!("\nUse 'reregister' to create a new identity.");
        return Ok(());
    }

    let response = if force {
        registrar.re_register(device_type, capabilities).await?
    } else {
        registrar.register(device_type, capabilities).await?
    };

    println!("\n✓ Device registered successfully!");
    println!("  DID: {}", response.did);
    println!("  Object ID: {}", response.object_id);
    println!("  Credential expires: {}", response.credential_expires_at);
    println!("\n  Private key stored securely in: {}/private_key.hex", config.storage.data_path.display());

    Ok(())
}

async fn show_identity(config: &DeviceClientConfig) -> Result<()> {
    let manager = IdentityManager::new(config).await?;
    
    let info = manager.info();
    println!("{}", info);
    
    if manager.is_initialized() {
        if manager.is_credential_expired() {
            println!("\n⚠ WARNING: Credential has expired! Run 'reregister' to get a new one.");
        } else if manager.credential_expires_soon(24) {
            println!("\n⚠ WARNING: Credential expires within 24 hours.");
        }
    }

    Ok(())
}

async fn sign_message(config: &DeviceClientConfig, message: &str) -> Result<()> {
    let manager = IdentityManager::new(config).await?;
    
    if !manager.is_initialized() {
        println!("Device not registered. Run 'register' first.");
        return Ok(());
    }
    
    let signature = manager.sign_challenge(message)?;
    
    println!("\nMessage: {}", message);
    println!("Signature: {}", signature);
    println!("\nPublic Key: {}", manager.public_key_hex().unwrap_or_default());
    println!("DID: {}", manager.did().unwrap_or("unknown"));

    Ok(())
}

async fn connect_to_device(config: &DeviceClientConfig, addr: &str) -> Result<()> {
    info!(addr = %addr, "Connecting to device");

    let manager = IdentityManager::new(config).await?;
    
    if !manager.is_initialized() {
        println!("Device not registered. Run 'register' first.");
        return Ok(());
    }
    
    let did = manager.did().unwrap().to_string();
    let credential_jwt = manager.credential_jwt().unwrap().to_string();
    let signing_key = manager.signing_key().ok_or_else(|| {
        anyhow::anyhow!("No signing key available")
    })?.clone();

    let resolver = Arc::new(DIDResolver::new(config).await?);
    
    let client = TlsClient::new(
        resolver,
        did,
        credential_jwt,
        signing_key,
        config.identity_service_url.clone(),
        config.tls.clone(),
    )?;

    let connection = client.connect(addr).await?;

    println!("\n✓ Connected and authenticated!");
    println!("  Peer DID: {}", connection.peer_did);
    println!("  Peer Public Key: {}...", &connection.peer_public_key[..16]);
    println!("\n  Metrics:");
    println!("    TLS Handshake: {}ms", connection.metrics.tls_handshake_ms);
    println!("    DID Auth: {}ms", connection.metrics.did_auth_ms);
    println!("    Credential Verify: {}ms", connection.metrics.credential_verify_ms);
    println!("    Challenge-Response: {}ms", connection.metrics.challenge_response_ms);
    println!("    Total: {}ms", connection.metrics.total_ms);

    // Keep connection open briefly
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    println!("\nConnection closed.");

    Ok(())
}

async fn start_server(config: &DeviceClientConfig, port: u16) -> Result<()> {
    info!(port = port, "Starting TLS server");

    let manager = IdentityManager::new(config).await?;
    
    if !manager.is_initialized() {
        println!("Device not registered. Run 'register' first.");
        return Ok(());
    }

    let did = manager.did().unwrap().to_string();
    let credential_jwt = manager.credential_jwt().unwrap().to_string();
    let signing_key = manager.signing_key().ok_or_else(|| {
        anyhow::anyhow!("No signing key available")
    })?.clone();

    let resolver = Arc::new(DIDResolver::new(config).await?);
    
    let server = TlsServer::new(
        resolver,
        did.clone(),
        credential_jwt,
        signing_key,
        config.identity_service_url.clone(),
        config.tls.clone(),
    )?;

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    println!("\n✓ Server listening on port {}", port);
    println!("  DID: {}", did);

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

async fn clear_storage(config: &DeviceClientConfig) -> Result<()> {
    println!("This will delete all stored device data including the private key.");
    println!("Are you sure? Type 'yes' to confirm:");
    
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    
    if input.trim().to_lowercase() == "yes" {
        let mut storage = device_client::SecureStorage::new(&config.storage).await?;
        storage.clear().await?;
        println!("✓ All device data cleared.");
    } else {
        println!("Cancelled.");
    }

    Ok(())
}

// La funzione rotate_key, aggiungila dopo clear_storage:
async fn rotate_key(config: &DeviceClientConfig) -> Result<()> {
    info!("Rotating device key...");

    let storage = device_client::SecureStorage::new(&config.storage).await?;

    // Load existing identity
    let identity = storage.load_identity().await?
        .ok_or_else(|| anyhow::anyhow!("No device identity found. Register first."))?;

    let did = identity.did.clone();
    println!("  Rotating key for DID: {}", did);

    // Generate new Ed25519 key pair
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let new_signing_key = SigningKey::generate(&mut OsRng);
    let new_public_key_hex = hex::encode(new_signing_key.verifying_key().as_bytes());
    let new_private_key_hex = hex::encode(new_signing_key.to_bytes());

    info!("Generated new Ed25519 keypair");

    // Write new private key to a temporary file first (crash safety)
    let data_dir = &config.storage.data_path;
    let tmp_key_path = data_dir.join("private_key.hex.new");
    let key_path = data_dir.join("private_key.hex");

    std::fs::write(&tmp_key_path, &new_private_key_hex)
        .map_err(|e| anyhow::anyhow!("Failed to write temporary key: {}", e))?;

    // Call the Identity Service to rotate the key on-chain
    let client = reqwest::Client::new();
    let did_encoded = urlencoding::encode(&did);
    let url = format!(
        "{}/api/v1/did/rotate-key/{}",
        config.identity_service_url, did_encoded
    );

    println!("  Submitting rotation to blockchain...");

    let response = client
        .post(&url)
        .json(&shared::types::KeyRotationRequest {
            new_public_key: new_public_key_hex.clone(),
        })
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to contact Identity Service: {}", e))?;

    if !response.status().is_success() {
        // Clean up temp file
        let _ = std::fs::remove_file(&tmp_key_path);
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Key rotation failed: {}", body));
    }

    let result: shared::types::KeyRotationResponse = response
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("Invalid response: {}", e))?;

    if !result.success {
        // Clean up temp file
        let _ = std::fs::remove_file(&tmp_key_path);
        return Err(anyhow::anyhow!(
            "Key rotation failed: {}",
            result.error.unwrap_or_else(|| "Unknown error".into())
        ));
    }

    // On-chain rotation succeeded, now replace the private key
    std::fs::rename(&tmp_key_path, &key_path)
        .map_err(|e| anyhow::anyhow!("Failed to update private key file: {}", e))?;

    println!("\n✓ Key rotated successfully!");
    println!("  DID: {}", did);
    if let Some(ref method_id) = result.new_verification_method_id {
        println!("  New verification method: {}", method_id);
    }
    println!("  New public key: {}...", &new_public_key_hex[..16]);
    println!("  Private key updated in: {}", key_path.display());

    Ok(())
}