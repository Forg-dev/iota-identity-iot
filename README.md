# IOTA Identity for IoT - Blockchain-based PKI Replacement

> Decentralized PKI system using IOTA Rebased for IoT device authentication

## Overview

This project demonstrates how **IOTA Rebased** can replace traditional PKI (Certificate Authorities) for TLS authentication between IoT devices.

### Key Features

- **DIDs** (Decentralized Identifiers) replace X.509 certificates
- **IOTA Rebased blockchain** replaces centralized Certificate Authorities  
- **Verifiable Credentials** replace CA-signed certificates
- **Scalable** to 100,000+ devices

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    IOTA Rebased Network                     │
│  ┌─────────────────┐  ┌─────────────────┐                   │
│  │ Identity Package│  │   DID Objects   │                   │
│  │  (Move Smart    │  │  (On-chain      │                   │
│  │   Contract)     │  │   Storage)      │                   │
│  └────────┬────────┘  └────────┬────────┘                   │
└───────────┼────────────────────┼────────────────────────────┘
            │                    │
    ┌───────┴────────────────────┴───────┐
    │         Identity Service           │
    │  ┌──────────┐  ┌──────────────┐    │
    │  │   DID    │  │  Credential  │    │
    │  │ Manager  │  │   Issuer     │    │
    │  └──────────┘  └──────────────┘    │
    │  ┌──────────┐  ┌──────────────┐    │
    │  │  Cache   │  │   REST API   │    │
    │  │ (Moka)   │  │   (Axum)     │    │
    │  └──────────┘  └──────────────┘    │
    └───────────────┬────────────────────┘
                    │
    ┌───────────────┼───────────────┐
    │               │               │
┌───┴───┐       ┌───┴───┐       ┌───┴───┐
│Device │       │Device │       │Device │
│Client │◄─────►│Client │◄─────►│Client │
│ (TLS) │       │ (TLS) │       │ (TLS) │
└───────┘       └───────┘       └───────┘
```

## IOTA Rebased vs Stardust

**IMPORTANT**: This project uses **IOTA Rebased** APIs, NOT the older Stardust APIs.

| Component | Stardust (OLD) | Rebased (NEW) |
|-----------|---------------|---------------|
| SDK | `iota-sdk` (crates.io) | `iota-sdk` (github.com/iotaledger/iota) |
| Identity | `identity_iota` v1.5 | `identity_iota` (github.com/iotaledger/identity) |
| Ledger | UTXO (Alias Outputs) | Object-based (Move VM) |
| Consensus | Nakamoto-like | Mysticeti (DPoS) |
| Fees | Feeless | Gas required |
| Client | `IotaIdentityClient` | `IdentityClient` / `IdentityClientReadOnly` |

## Project Structure

```
iota-identity-iot/
├── Cargo.toml                 # Workspace configuration
├── shared/                    # Shared types, errors, constants
│   └── src/
│       ├── lib.rs
│       ├── config.rs          # Configuration management
│       ├── constants.rs       # IOTA endpoints, Package IDs
│       ├── error.rs           # Error types
│       └── types.rs           # Data structures
├── identity-service/          # Backend service
│   └── src/
│       ├── main.rs            # Service entry point
│       ├── lib.rs
│       ├── api/               # REST API (Axum)
│       │   └── mod.rs
│       ├── cache/             # DID & Credential caching
│       │   └── mod.rs
│       ├── credential/        # W3C VC issuance
│       │   └── mod.rs
│       └── did/               # IOTA Rebased DID operations
│           └── mod.rs
├── device-client/             # Client library & CLI
│   └── src/
│       ├── main.rs            # CLI entry point
│       ├── lib.rs
│       ├── registration/      # Device registration
│       │   └── mod.rs
│       ├── resolver/          # DID resolution
│       │   └── mod.rs
│       ├── storage/           # Secure local storage
│       │   └── mod.rs
│       └── tls/               # TLS with DID auth
│           └── mod.rs
├── docs/                      # Documentation
├── examples/                  # Example code
├── benches/                   # Benchmarks
└── scripts/                   # Utility scripts
```

## Quick Start

### Prerequisites

```bash
# Rust (latest stable)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Required environment variables
export IOTA_IDENTITY_PKG_ID=0x222741bbdff74b42df48a7b4733185e9b24becb8ccfbafe8eac864ab4e4cc555
export STRONGHOLD_PASSWORD=your_secure_password
export IOTA_NETWORK=testnet
```

### Build

```bash
cd iota-identity-iot
cargo build --release
```

### Run Identity Service

```bash
cargo run --release --bin identity-service
```

### Register a Device

```bash
cargo run --release --bin device-client -- register \
    --type sensor \
    --capabilities temperature,humidity
```

### Test TLS Connection

```bash
# Terminal 1: Start server
cargo run --release --bin device-client -- server --port 8443

# Terminal 2: Connect as client
cargo run --release --bin device-client -- connect --addr localhost:8443
```

## API Endpoints

### Identity Service (default: http://localhost:8080)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/api/v1/device/register` | Register new device |
| GET | `/api/v1/did/resolve/:did` | Resolve DID |
| POST | `/api/v1/credential/verify` | Verify credential |
| GET | `/metrics` | Service metrics |

### Example: Register Device

```bash
curl -X POST http://localhost:8080/api/v1/device/register \
  -H "Content-Type: application/json" \
  -d '{
    "public_key": "a1b2c3...64_hex_chars",
    "device_type": "sensor",
    "capabilities": ["temperature", "humidity"]
  }'
```

Response:
```json
{
  "did": "did:iota:0x...",
  "object_id": "0x...",
  "credential_jwt": "eyJ...",
  "credential_expires_at": "2026-01-30T00:00:00Z"
}
```

## TLS + DID Authentication Protocol

```
┌────────┐                                         ┌────────┐
│ Client │                                         │ Server │
└───┬────┘                                         └───┬────┘
    │                                                  │
    │──────────── TCP Connect ────────────────────────►│
    │                                                  │
    │◄─────────── TLS Handshake ─────────────────────►│
    │         (self-signed certs OK)                   │
    │                                                  │
    │──────────── DID Auth Hello ─────────────────────►│
    │         {did, credential_jwt, challenge}         │
    │                                                  │
    │◄─────────── DID Auth Hello ──────────────────────│
    │         {did, credential_jwt, challenge}         │
    │                                                  │
    │  ┌─────────────────────────────────────────┐     │
    │  │ Both verify DIDs via IOTA blockchain    │     │
    │  │ - Resolve DID Document                  │     │
    │  │ - Verify credential signature           │     │
    │  │ - Check expiration/revocation           │     │
    │  └─────────────────────────────────────────┘     │
    │                                                  │
    │◄─────────── Auth Success ────────────────────────│
    │                                                  │
    │═══════════ Authenticated Channel ═══════════════│
    │                                                  │
```

## Benchmarking

Benchmarks are planned for:

- TLS handshake latency (with/without cache)
- DID resolution time
- Credential verification time
- Throughput (connections/second)
- Memory usage per device
- Scalability to 100,000 devices

## Dependencies

### IOTA Rebased (from GitHub)

```toml
# Cargo.toml - USE THESE (not crates.io!)
identity_iota = { git = "https://github.com/iotaledger/identity", branch = "main" }
iota-sdk = { git = "https://github.com/iotaledger/iota", package = "iota-sdk" }
```

### Key Libraries

- `identity_iota` - IOTA DID operations
- `identity_stronghold` - Secure key storage
- `tokio` - Async runtime
- `axum` - HTTP framework
- `rustls` / `tokio-rustls` - TLS
- `moka` - High-performance caching
- `ed25519-dalek` - Cryptography

## License

MIT OR Apache-2.0

## References

- [IOTA Identity Docs](https://docs.iota.org/iota-identity)
- [IOTA Identity Workshop](https://docs.iota.org/developer/workshops/identity-workshop)
- [W3C DID Specification](https://www.w3.org/TR/did-core/)
- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/)
