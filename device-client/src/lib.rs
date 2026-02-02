//! # Device Client for IOTA Rebased IoT Authentication
//!
//! This crate provides client-side functionality for IoT devices:
//! - Registration with Identity Service
//! - DID resolution from blockchain
//! - Credential verification
//! - TLS with DID-based authentication
//! - Secure local storage
//!
//! ## IOTA Rebased
//!
//! This client uses IOTA Rebased APIs for blockchain interaction.
//! Key differences from Stardust:
//! - Object-based ledger (Move VM)
//! - Gas fees required for transactions
//! - Different SDK and client APIs

pub mod identity;
pub mod resolver;
pub mod storage;
pub mod tls;
pub mod registration;

// Re-export commonly used types
pub use identity::IdentityManager;
pub use resolver::DIDResolver;
pub use storage::SecureStorage;
pub use tls::{TlsClient, TlsServer, AuthenticatedConnection, AuthenticationMetrics, CredentialVerifier};
pub use registration::DeviceRegistrar;