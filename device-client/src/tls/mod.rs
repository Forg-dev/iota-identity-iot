//! # TLS with DID Authentication
//!
//! Provides TLS communication with blockchain-based authentication:
//! 1. Standard TLS handshake (with self-signed certificates)
//! 2. Post-handshake DID authentication with challenge-response
//! 3. Credential exchange and verification
//!
//! ## Protocol Flow
//!
//! ```text
//! Client                                Server
//!   |                                     |
//!   |-------- TLS Handshake ------------->|
//!   |<------- TLS Established ------------|
//!   |                                     |
//!   |-- Hello (DID, JWT, challenge) ----->|
//!   |                                     | (verify JWT, check revocation)
//!   |<-- Hello (DID, JWT, challenge, -----|
//!   |         response to client challenge)|
//!   |                                     |
//!   | (verify JWT, check revocation,      |
//!   |  verify challenge response)         |
//!   |                                     |
//!   |-- Response (to server challenge) -->|
//!   |                                     | (verify challenge response)
//!   |<------- Success / Failure ----------|
//!   |                                     |
//!   |====== Secure Communication =========|
//! ```
//!
//! ## Security Properties
//!
//! - **Confidentiality**: TLS encryption (AES-256-GCM)
//! - **Authentication**: DID-based with Verifiable Credentials
//! - **Non-repudiation**: Challenge-response proves key possession
//! - **Revocation**: On-chain RevocationBitmap2022 check

mod verifier;

pub use verifier::{CredentialVerifier, ParsedCredential, verify_challenge_response};

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

use ed25519_dalek::{SigningKey, Signer};
use rustls::{
    ClientConfig, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
};
use tokio_rustls::{TlsAcceptor, TlsConnector, client::TlsStream as ClientTlsStream, server::TlsStream as ServerTlsStream};
use rcgen::{generate_simple_self_signed, CertifiedKey};

use shared::{
    config::TlsConfig,
    error::{IdentityError, IdentityResult},
    types::{DIDAuthMessage, DIDAuthMessageType},
};

use crate::resolver::DIDResolver;

/// Result of TLS + DID authentication with timing metrics
#[derive(Debug, Clone)]
pub struct AuthenticationMetrics {
    /// TLS handshake duration
    pub tls_handshake_ms: u64,
    
    /// DID authentication duration (credential exchange + verification)
    pub did_auth_ms: u64,
    
    /// Credential verification duration
    pub credential_verify_ms: u64,
    
    /// Challenge-response duration
    pub challenge_response_ms: u64,
    
    /// Revocation check duration
    pub revocation_check_ms: u64,
    
    /// Total authentication duration
    pub total_ms: u64,
}

/// TLS Client with DID authentication
pub struct TlsClient {
    /// TLS connector
    connector: TlsConnector,
    
    /// DID Resolver for verifying server's DID
    #[allow(dead_code)]
    resolver: Arc<DIDResolver>,
    
    /// Credential verifier
    verifier: Arc<CredentialVerifier>,
    
    /// This device's DID
    device_did: String,
    
    /// This device's credential JWT
    credential_jwt: String,
    
    /// This device's public key (hex)
    public_key_hex: String,
    
    /// This device's signing key for challenge-response
    signing_key: SigningKey,
    
    /// Configuration
    config: TlsConfig,
}

impl TlsClient {
    /// Create a new TLS client
    pub fn new(
        resolver: Arc<DIDResolver>,
        device_did: String,
        credential_jwt: String,
        signing_key: SigningKey,
        identity_service_url: String,
        config: TlsConfig,
    ) -> IdentityResult<Self> {
        // Create credential verifier
        let verifier = Arc::new(CredentialVerifier::new(
            resolver.clone(),
            identity_service_url,
            config.verify_revocation,
        ));
        
        // Get public key hex for challenge-response verification
        let public_key_hex = hex::encode(signing_key.verifying_key().as_bytes());
        
        // Create TLS config that accepts any certificate
        // (we verify identity via DID, not certificate)
        let tls_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCertVerifier))
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(tls_config));

        Ok(Self {
            connector,
            resolver,
            verifier,
            device_did,
            credential_jwt,
            public_key_hex,
            signing_key,
            config,
        })
    }

    /// Connect to a server and perform DID authentication
    pub async fn connect(&self, addr: &str) -> IdentityResult<AuthenticatedConnection<ClientTlsStream<TcpStream>>> {
        let total_start = Instant::now();
        info!(addr = %addr, "Connecting to server");

        // TCP connection
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| IdentityError::NetworkConnectionError {
                endpoint: addr.to_string(),
                reason: e.to_string(),
            })?;

        // TLS handshake
        let tls_start = Instant::now();
        let server_name = ServerName::try_from("localhost".to_string())
            .map_err(|_| IdentityError::TLSHandshakeError("Invalid server name".into()))?;

        let mut tls_stream = tokio::time::timeout(
            Duration::from_secs(self.config.handshake_timeout_secs),
            self.connector.connect(server_name, stream),
        )
        .await
        .map_err(|_| IdentityError::ConnectionTimeout {
            timeout_secs: self.config.handshake_timeout_secs,
        })?
        .map_err(|e| IdentityError::TLSHandshakeError(e.to_string()))?;
        
        let tls_handshake_ms = tls_start.elapsed().as_millis() as u64;
        debug!(duration_ms = tls_handshake_ms, "TLS handshake completed");

        // DID Authentication
        let did_auth_start = Instant::now();
        let (server_did, peer_public_key, credential_verify_ms, challenge_response_ms, revocation_check_ms) = 
            self.perform_did_auth(&mut tls_stream).await?;
        let did_auth_ms = did_auth_start.elapsed().as_millis() as u64;

        let total_ms = total_start.elapsed().as_millis() as u64;
        
        let metrics = AuthenticationMetrics {
            tls_handshake_ms,
            did_auth_ms,
            credential_verify_ms,
            challenge_response_ms,
            revocation_check_ms,
            total_ms,
        };

        info!(
            server_did = %server_did,
            total_ms = total_ms,
            "DID authentication successful"
        );

        Ok(AuthenticatedConnection {
            stream: tls_stream,
            peer_did: server_did,
            peer_public_key,
            metrics,
        })
    }

    /// Perform DID authentication after TLS handshake
    async fn perform_did_auth(
        &self, 
        stream: &mut ClientTlsStream<TcpStream>
    ) -> IdentityResult<(String, String, u64, u64, u64)> {
        // Generate challenge for server
        let our_challenge = generate_challenge();
        
        // Send our hello with DID, credential, and challenge
        let hello = DIDAuthMessage {
            message_type: DIDAuthMessageType::Hello,
            did: self.device_did.clone(),
            credential_jwt: self.credential_jwt.clone(),
            challenge: Some(our_challenge.clone()),
            challenge_response: None,
            public_key: Some(self.public_key_hex.clone()),
            timestamp: chrono::Utc::now(),
        };

        send_message(stream, &hello).await?;
        debug!("Sent DID auth hello with challenge");

        // Receive server's hello (with their credential and response to our challenge)
        let server_hello: DIDAuthMessage = receive_message(stream).await?;
        debug!(server_did = %server_hello.did, "Received server DID auth hello");

        // Verify server's credential
        let verify_start = Instant::now();
        let _credential = self.verifier
            .verify_credential(&server_hello.credential_jwt, &server_hello.did)
            .await?;
        let credential_verify_ms = verify_start.elapsed().as_millis() as u64;
        
        // Get server's public key
        let server_public_key = server_hello.public_key.ok_or_else(|| {
            IdentityError::DIDAuthenticationError("Server did not provide public key".into())
        })?;
        
        // Verify that the server's public key is in their DID Document (prevents impersonation)
        self.verifier.verify_public_key_binding(&server_hello.did, &server_public_key).await?;
        debug!("Server public key binding verified against DID Document");
        
        // Verify server's response to our challenge
        let challenge_start = Instant::now();
        let server_response = server_hello.challenge_response.ok_or_else(|| {
            IdentityError::DIDAuthenticationError("Server did not respond to challenge".into())
        })?;
        
        let valid = verify_challenge_response(&our_challenge, &server_response, &server_public_key)?;
        if !valid {
            return Err(IdentityError::DIDAuthenticationError(
                "Server challenge response invalid".into()
            ));
        }
        let challenge_response_ms = challenge_start.elapsed().as_millis() as u64;
        debug!("Server challenge-response verified");
        
        // Sign server's challenge
        let server_challenge = server_hello.challenge.ok_or_else(|| {
            IdentityError::DIDAuthenticationError("Server did not send challenge".into())
        })?;
        
        let our_response = self.signing_key.sign(server_challenge.as_bytes());
        let our_response_hex = hex::encode(our_response.to_bytes());
        
        // Send our response
        let response_msg = DIDAuthMessage {
            message_type: DIDAuthMessageType::Response,
            did: self.device_did.clone(),
            credential_jwt: String::new(),
            challenge: None,
            challenge_response: Some(our_response_hex),
            public_key: None,
            timestamp: chrono::Utc::now(),
        };
        
        send_message(stream, &response_msg).await?;
        debug!("Sent challenge response");

        // Wait for success/failure
        let result: DIDAuthMessage = receive_message(stream).await?;
        
        if result.message_type != DIDAuthMessageType::Success {
            return Err(IdentityError::DIDAuthenticationError(
                "Server rejected authentication".into()
            ));
        }

        // Revocation check time is included in credential verification for now
        let revocation_check_ms = 0;

        Ok((
            server_hello.did,
            server_public_key,
            credential_verify_ms,
            challenge_response_ms,
            revocation_check_ms,
        ))
    }
}

/// TLS Server with DID authentication
pub struct TlsServer {
    /// TLS acceptor
    acceptor: TlsAcceptor,
    
    /// DID Resolver
    #[allow(dead_code)]
    resolver: Arc<DIDResolver>,
    
    /// Credential verifier
    verifier: Arc<CredentialVerifier>,
    
    /// This server's DID
    server_did: String,
    
    /// This server's credential JWT
    credential_jwt: String,
    
    /// This server's public key (hex)
    public_key_hex: String,
    
    /// This server's signing key for challenge-response
    signing_key: SigningKey,
    
    /// Configuration
    #[allow(dead_code)]
    config: TlsConfig,
}

impl TlsServer {
    /// Create a new TLS server
    pub fn new(
        resolver: Arc<DIDResolver>,
        server_did: String,
        credential_jwt: String,
        signing_key: SigningKey,
        identity_service_url: String,
        config: TlsConfig,
    ) -> IdentityResult<Self> {
        // Create credential verifier
        let verifier = Arc::new(CredentialVerifier::new(
            resolver.clone(),
            identity_service_url,
            config.verify_revocation,
        ));
        
        // Get public key hex
        let public_key_hex = hex::encode(signing_key.verifying_key().as_bytes());
        
        // Generate self-signed certificate for TLS
        let CertifiedKey { cert, key_pair } = generate_simple_self_signed(vec!["localhost".into()])
            .map_err(|e| IdentityError::TLSCertificateError(e.to_string()))?;

        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::try_from(key_pair.serialize_der())
            .map_err(|e| IdentityError::TLSCertificateError(e.to_string()))?;

        let tls_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .map_err(|e| IdentityError::TLSCertificateError(e.to_string()))?;

        let acceptor = TlsAcceptor::from(Arc::new(tls_config));

        Ok(Self {
            acceptor,
            resolver,
            verifier,
            server_did,
            credential_jwt,
            public_key_hex,
            signing_key,
            config,
        })
    }
    
    /// Get the TLS acceptor for accepting raw connections
    pub fn acceptor(&self) -> &TlsAcceptor {
        &self.acceptor
    }

    /// Accept a connection and perform DID authentication
    pub async fn accept(&self, stream: TcpStream) -> IdentityResult<AuthenticatedConnection<ServerTlsStream<TcpStream>>> {
        let total_start = Instant::now();
        let peer_addr = stream.peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".into());

        info!(peer = %peer_addr, "Accepting connection");

        // TLS handshake
        let tls_start = Instant::now();
        let mut tls_stream = self.acceptor.accept(stream)
            .await
            .map_err(|e| IdentityError::TLSHandshakeError(e.to_string()))?;
        
        let tls_handshake_ms = tls_start.elapsed().as_millis() as u64;
        debug!(duration_ms = tls_handshake_ms, "TLS handshake completed");

        // DID Authentication
        let did_auth_start = Instant::now();
        let (client_did, peer_public_key, credential_verify_ms, challenge_response_ms, revocation_check_ms) = 
            self.perform_did_auth(&mut tls_stream).await?;
        let did_auth_ms = did_auth_start.elapsed().as_millis() as u64;
        
        let total_ms = total_start.elapsed().as_millis() as u64;
        
        let metrics = AuthenticationMetrics {
            tls_handshake_ms,
            did_auth_ms,
            credential_verify_ms,
            challenge_response_ms,
            revocation_check_ms,
            total_ms,
        };

        info!(
            client_did = %client_did,
            total_ms = total_ms,
            "Client authenticated"
        );

        Ok(AuthenticatedConnection {
            stream: tls_stream,
            peer_did: client_did,
            peer_public_key,
            metrics,
        })
    }

    /// Perform DID authentication with client
    async fn perform_did_auth(
        &self, 
        stream: &mut ServerTlsStream<TcpStream>
    ) -> IdentityResult<(String, String, u64, u64, u64)> {
        // Receive client's hello
        let client_hello: DIDAuthMessage = receive_message(stream).await?;
        debug!(client_did = %client_hello.did, "Received client DID auth hello");

        // Verify client's credential
        let verify_start = Instant::now();
        let _credential = self.verifier
            .verify_credential(&client_hello.credential_jwt, &client_hello.did)
            .await?;
        let credential_verify_ms = verify_start.elapsed().as_millis() as u64;
        
        // Get client's public key
        let client_public_key = client_hello.public_key.ok_or_else(|| {
            IdentityError::DIDAuthenticationError("Client did not provide public key".into())
        })?;
        
        // Verify that the client's public key is in their DID Document (prevents impersonation)
        self.verifier.verify_public_key_binding(&client_hello.did, &client_public_key).await?;
        debug!("Client public key binding verified against DID Document");
        
        // Get client's challenge
        let client_challenge = client_hello.challenge.ok_or_else(|| {
            IdentityError::DIDAuthenticationError("Client did not send challenge".into())
        })?;
        
        // Sign client's challenge
        let our_response = self.signing_key.sign(client_challenge.as_bytes());
        let our_response_hex = hex::encode(our_response.to_bytes());
        
        // Generate our challenge for client
        let our_challenge = generate_challenge();

        // Send our hello with response to client's challenge and our challenge
        let hello = DIDAuthMessage {
            message_type: DIDAuthMessageType::Hello,
            did: self.server_did.clone(),
            credential_jwt: self.credential_jwt.clone(),
            challenge: Some(our_challenge.clone()),
            challenge_response: Some(our_response_hex),
            public_key: Some(self.public_key_hex.clone()),
            timestamp: chrono::Utc::now(),
        };

        send_message(stream, &hello).await?;
        debug!("Sent DID auth hello with challenge response");
        
        // Receive client's response to our challenge
        let client_response: DIDAuthMessage = receive_message(stream).await?;
        
        if client_response.message_type != DIDAuthMessageType::Response {
            return Err(IdentityError::DIDAuthenticationError(
                "Expected challenge response from client".into()
            ));
        }
        
        // Verify client's response
        let challenge_start = Instant::now();
        let response = client_response.challenge_response.ok_or_else(|| {
            IdentityError::DIDAuthenticationError("Client did not provide challenge response".into())
        })?;
        
        let valid = verify_challenge_response(&our_challenge, &response, &client_public_key)?;
        if !valid {
            // Send failure
            let failure = DIDAuthMessage {
                message_type: DIDAuthMessageType::Failure,
                did: self.server_did.clone(),
                credential_jwt: String::new(),
                challenge: None,
                challenge_response: None,
                public_key: None,
                timestamp: chrono::Utc::now(),
            };
            send_message(stream, &failure).await?;
            
            return Err(IdentityError::DIDAuthenticationError(
                "Client challenge response invalid".into()
            ));
        }
        let challenge_response_ms = challenge_start.elapsed().as_millis() as u64;
        debug!("Client challenge-response verified");

        // Send success
        let success = DIDAuthMessage {
            message_type: DIDAuthMessageType::Success,
            did: self.server_did.clone(),
            credential_jwt: String::new(),
            challenge: None,
            challenge_response: None,
            public_key: None,
            timestamp: chrono::Utc::now(),
        };

        send_message(stream, &success).await?;

        let revocation_check_ms = 0;

        Ok((
            client_hello.did,
            client_public_key,
            credential_verify_ms,
            challenge_response_ms,
            revocation_check_ms,
        ))
    }
}

/// An authenticated TLS connection with metrics
pub struct AuthenticatedConnection<S> {
    /// The TLS stream
    pub stream: S,
    
    /// The authenticated peer's DID
    pub peer_did: String,
    
    /// The peer's public key (hex)
    pub peer_public_key: String,
    
    /// Authentication metrics
    pub metrics: AuthenticationMetrics,
}

impl<S> AuthenticatedConnection<S> {
    /// Get the peer's DID
    pub fn peer_did(&self) -> &str {
        &self.peer_did
    }
    
    /// Get authentication metrics
    pub fn metrics(&self) -> &AuthenticationMetrics {
        &self.metrics
    }
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Generate a random challenge for authentication
fn generate_challenge() -> String {
    use rand::Rng;
    let bytes: [u8; 32] = rand::thread_rng().gen();
    hex::encode(bytes)
}

/// Send a message over the stream
async fn send_message<S, M>(stream: &mut S, message: &M) -> IdentityResult<()>
where
    S: AsyncWriteExt + Unpin,
    M: serde::Serialize,
{
    let json = serde_json::to_vec(message)
        .map_err(|e| IdentityError::SerializationError(e.to_string()))?;

    // Send length prefix (4 bytes, big-endian)
    let len = (json.len() as u32).to_be_bytes();
    stream.write_all(&len).await
        .map_err(|e| IdentityError::NetworkConnectionError {
            endpoint: "stream".into(),
            reason: e.to_string(),
        })?;

    // Send message
    stream.write_all(&json).await
        .map_err(|e| IdentityError::NetworkConnectionError {
            endpoint: "stream".into(),
            reason: e.to_string(),
        })?;

    stream.flush().await
        .map_err(|e| IdentityError::NetworkConnectionError {
            endpoint: "stream".into(),
            reason: e.to_string(),
        })?;

    Ok(())
}

/// Receive a message from the stream
async fn receive_message<S, M>(stream: &mut S) -> IdentityResult<M>
where
    S: AsyncReadExt + Unpin,
    M: serde::de::DeserializeOwned,
{
    // Read length prefix
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await
        .map_err(|e| IdentityError::NetworkConnectionError {
            endpoint: "stream".into(),
            reason: e.to_string(),
        })?;

    let len = u32::from_be_bytes(len_bytes) as usize;

    // Sanity check
    if len > 1024 * 1024 {
        return Err(IdentityError::InvalidRequest("Message too large".into()));
    }

    // Read message
    let mut buffer = vec![0u8; len];
    stream.read_exact(&mut buffer).await
        .map_err(|e| IdentityError::NetworkConnectionError {
            endpoint: "stream".into(),
            reason: e.to_string(),
        })?;

    serde_json::from_slice(&buffer)
        .map_err(|e| IdentityError::SerializationError(e.to_string()))
}

/// Certificate verifier that accepts any certificate
/// (We verify identity via DID, not certificates)
#[derive(Debug)]
struct AcceptAnyCertVerifier;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Accept any certificate - we verify via DID
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_generation() {
        let challenge1 = generate_challenge();
        let challenge2 = generate_challenge();
        
        assert_eq!(challenge1.len(), 64); // 32 bytes = 64 hex chars
        assert_ne!(challenge1, challenge2);
    }
    
    #[test]
    fn test_authentication_metrics_default() {
        let metrics = AuthenticationMetrics {
            tls_handshake_ms: 50,
            did_auth_ms: 100,
            credential_verify_ms: 30,
            challenge_response_ms: 5,
            revocation_check_ms: 10,
            total_ms: 165,
        };
        
        assert_eq!(metrics.total_ms, 165);
    }
}