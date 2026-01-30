//! # Shared Module for IOTA Identity IoT System
//!
//! This crate provides common types, errors, and utilities used across
//! the Identity Service and Device Client components.
//!
//! ## Architecture
//!
//! This system replaces traditional PKI (Certificate Authorities) with:
//! - **DIDs** (Decentralized Identifiers) instead of X.509 certificates
//! - **IOTA Rebased blockchain** as the source of truth instead of CAs
//! - **Verifiable Credentials** instead of CA-signed certificates
//!
//! ## IOTA Rebased vs Stardust
//!
//! This implementation uses **IOTA Rebased** APIs, which are fundamentally
//! different from the older Stardust APIs:
//!
//! | Component | Stardust | Rebased |
//! |-----------|----------|---------|
//! | Ledger | UTXO (Alias Outputs) | Object-based (Move VM) |
//! | Identity Client | `IotaIdentityClient` | `IdentityClient` |
//! | SDK | `iota-sdk` (crates.io) | `iota-sdk` (github) |
//! | Fees | Feeless | Gas required |

pub mod config;
pub mod constants;
pub mod error;
pub mod types;

// Re-exports for convenience
pub use config::*;
pub use constants::*;
pub use error::*;
pub use types::*;

/// Crate version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");










