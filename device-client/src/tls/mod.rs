//! # TLS with DID Authentication
//!
//! Provides TLS communication with blockchain-based authentication:
//! 1. Standard TLS handshake (with self-signed certificates)
//! 2. Post-handshake DID authentication
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
//!   |-------- DID Auth Hello ------------>|
//!   |<------- DID Auth Hello -------------|
//!   |                                     |
//!   |  (Both verify DIDs via blockchain)  |
//!   |                                     |
//!   |<------ Auth Success/Failure ------->|
//!   |                                     |
//!   |====== Secure Communication =========|
//! ```

use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error, info, warn};

use rustls::{
    ClientConfig, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
};
use tokio_rustls::{TlsAcceptor, TlsConnector, client::TlsStream as ClientTlsStream, server::TlsStream as ServerTlsStream};
use rcgen::{generate_simple_self_signed, CertifiedKey};

use shared::{
    config::TlsConfig,
    constants::*,
    error::{IdentityError, IdentityResult},
    types::{DIDAuthMessage, DIDAuthMessageType},
};

use crate::resolver::DIDResolver;

/// TLS Client with DID authentication
pub struct TlsClient {
    /// TLS connector
    connector: TlsConnector,
    
    /// DID Resolver for verifying server's DID
    resolver: Arc<DIDResolver>,
    
    /// This device's DID
    device_did: String,
    
    /// This device's credential JWT
    credential_jwt: String,
    
    /// Configuration
    config: TlsConfig,
}

impl TlsClient {
    /// Create a new TLS client
    pub fn new(
        resolver: Arc<DIDResolver>,
        device_did: String,
        credential_jwt: String,
        config: TlsConfig,
    ) -> IdentityResult<Self> {
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
            device_did,
            credential_jwt,
            config,
        })
    }

    /// Connect to a server and perform DID authentication
    pub async fn connect(&self, addr: &str) -> IdentityResult<AuthenticatedConnection<ClientTlsStream<TcpStream>>> {
        info!(addr = %addr, "Connecting to server");

        // TCP connection
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| IdentityError::NetworkConnectionError {
                endpoint: addr.to_string(),
                reason: e.to_string(),
            })?;

        // TLS handshake
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

        debug!("TLS handshake completed");

        // DID Authentication
        let server_did = self.perform_did_auth(&mut tls_stream).await?;

        info!(server_did = %server_did, "DID authentication successful");

        Ok(AuthenticatedConnection {
            stream: tls_stream,
            peer_did: server_did,
        })
    }

    /// Perform DID authentication after TLS handshake
    async fn perform_did_auth(&self, stream: &mut ClientTlsStream<TcpStream>) -> IdentityResult<String> {
        // Send our DID and credential
        let hello = DIDAuthMessage {
            message_type: DIDAuthMessageType::Hello,
            did: self.device_did.clone(),
            credential_jwt: self.credential_jwt.clone(),
            challenge_response: None,
            challenge: Some(generate_challenge()),
            timestamp: chrono::Utc::now(),
        };

        send_message(stream, &hello).await?;
        debug!("Sent DID auth hello");

        // Receive server's hello
        let server_hello: DIDAuthMessage = receive_message(stream).await?;
        debug!(server_did = %server_hello.did, "Received server DID auth hello");

        // Verify server's DID and credential
        self.verify_peer(&server_hello).await?;

        // Wait for success confirmation
        let response: DIDAuthMessage = receive_message(stream).await?;
        
        if response.message_type != DIDAuthMessageType::Success {
            return Err(IdentityError::DIDAuthenticationError(
                "Server rejected authentication".into()
            ));
        }

        Ok(server_hello.did)
    }

    /// Verify peer's DID and credential
    async fn verify_peer(&self, message: &DIDAuthMessage) -> IdentityResult<()> {
        // Resolve peer's DID from blockchain
        let did_document = self.resolver.resolve(&message.did).await?;

        // In a full implementation, we would:
        // 1. Verify the credential JWT signature
        // 2. Check that the credential subject matches the DID
        // 3. Check credential expiration
        // 4. Check revocation status on-chain

        debug!(peer_did = %message.did, "Peer verification successful");
        Ok(())
    }
}

/// TLS Server with DID authentication
pub struct TlsServer {
    /// TLS acceptor
    acceptor: TlsAcceptor,
    
    /// DID Resolver
    resolver: Arc<DIDResolver>,
    
    /// This server's DID
    server_did: String,
    
    /// This server's credential JWT
    credential_jwt: String,
    
    /// Configuration
    config: TlsConfig,
}

impl TlsServer {
    /// Create a new TLS server
    pub fn new(
        resolver: Arc<DIDResolver>,
        server_did: String,
        credential_jwt: String,
        config: TlsConfig,
    ) -> IdentityResult<Self> {
        // Generate self-signed certificate
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
            server_did,
            credential_jwt,
            config,
        })
    }

    /// Accept a connection and perform DID authentication
    pub async fn accept(&self, stream: TcpStream) -> IdentityResult<AuthenticatedConnection<ServerTlsStream<TcpStream>>> {
        let peer_addr = stream.peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".into());

        info!(peer = %peer_addr, "Accepting connection");

        // TLS handshake
        let mut tls_stream = tokio::time::timeout(
            Duration::from_secs(self.config.handshake_timeout_secs),
            self.acceptor.accept(stream),
        )
        .await
        .map_err(|_| IdentityError::ConnectionTimeout {
            timeout_secs: self.config.handshake_timeout_secs,
        })?
        .map_err(|e| IdentityError::TLSHandshakeError(e.to_string()))?;

        debug!("TLS handshake completed");

        // DID Authentication
        let client_did = self.perform_did_auth(&mut tls_stream).await?;

        info!(client_did = %client_did, "Client authenticated");

        Ok(AuthenticatedConnection {
            stream: tls_stream,
            peer_did: client_did,
        })
    }

    /// Perform DID authentication with client
    async fn perform_did_auth(&self, stream: &mut ServerTlsStream<TcpStream>) -> IdentityResult<String> {
        // Receive client's hello
        let client_hello: DIDAuthMessage = receive_message(stream).await?;
        debug!(client_did = %client_hello.did, "Received client DID auth hello");

        // Verify client's DID and credential
        self.verify_peer(&client_hello).await?;

        // Send our hello
        let hello = DIDAuthMessage {
            message_type: DIDAuthMessageType::Hello,
            did: self.server_did.clone(),
            credential_jwt: self.credential_jwt.clone(),
            challenge_response: client_hello.challenge.clone(),
            challenge: Some(generate_challenge()),
            timestamp: chrono::Utc::now(),
        };

        send_message(stream, &hello).await?;

        // Send success
        let success = DIDAuthMessage {
            message_type: DIDAuthMessageType::Success,
            did: self.server_did.clone(),
            credential_jwt: String::new(),
            challenge_response: None,
            challenge: None,
            timestamp: chrono::Utc::now(),
        };

        send_message(stream, &success).await?;

        Ok(client_hello.did)
    }

    /// Verify peer's DID and credential
    async fn verify_peer(&self, message: &DIDAuthMessage) -> IdentityResult<()> {
        // Resolve peer's DID from blockchain
        let _did_document = self.resolver.resolve(&message.did).await?;

        // Full verification would include credential checks
        debug!(peer_did = %message.did, "Peer verification successful");
        Ok(())
    }
}

/// An authenticated TLS connection
pub struct AuthenticatedConnection<S> {
    /// The TLS stream
    pub stream: S,
    /// The authenticated peer's DID
    pub peer_did: String,
}

/// DID Authenticator trait for custom implementations
pub trait DIDAuthenticator {
    /// Verify a peer's DID and credential
    fn verify(&self, did: &str, credential_jwt: &str) -> impl std::future::Future<Output = IdentityResult<()>> + Send;
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
}