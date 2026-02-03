# IOTA Identity IoT

A decentralized identity management system for IoT devices using IOTA Rebased blockchain, replacing traditional PKI with W3C DIDs and Verifiable Credentials.

## Overview

This system provides a complete solution for IoT device identity management without relying on centralized Certificate Authorities. Instead of X.509 certificates, devices receive **Decentralized Identifiers (DIDs)** stored on the IOTA blockchain and **Verifiable Credentials** signed by a trusted issuer.

### Key Features

- **Decentralized Trust**: No single point of failure - trust is anchored in blockchain consensus
- **W3C Standards Compliant**: DIDs (v1.0) and Verifiable Credentials (v2.0)
- **On-Chain Revocation**: RevocationBitmap2022 for instant, verifiable credential revocation
- **TLS Integration**: Mutual TLS authentication using DID-based credentials
- **Offline Verification**: Once cached, credentials can be verified without network access
- **150x Faster Revocation**: 0.13ms vs 19-20ms for traditional OCSP

### Performance Highlights

| Operation | Time | Comparison |
|-----------|------|------------|
| Revocation Check | 0.13ms | 150x faster than OCSP |
| DID Resolution (cached) | 0.13ms | Local lookup |
| Credential Verification | 0.24ms | Signature + revocation |
| Device Registration | ~1s | One-time setup |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         SYSTEM ARCHITECTURE                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   IoT Device                  Identity Service              Blockchain   │
│   ┌──────────┐               ┌──────────────┐             ┌──────────┐  │
│   │  Device  │ ──register──► │ DID Manager  │ ──publish─► │   IOTA   │  │
│   │  Client  │               │              │             │ Rebased  │  │
│   │          │ ◄──DID+JWT─── │ Credential   │ ◄──resolve─ │          │  │
│   │          │               │ Issuer       │             │          │  │
│   └──────────┘               │              │             │          │  │
│        │                     │ Revocation   │             │          │  │
│        │                     │ Manager      │             │          │  │
│        ▼                     └──────────────┘             └──────────┘  │
│   ┌──────────┐                      │                          ▲        │
│   │ Verifier │ ◄───resolve DID──────┘                          │        │
│   │          │ ◄───check bitmap────────────────────────────────┘        │
│   └──────────┘                                                          │
│                                                                          │
│   Flow:                                                                  │
│   1. Device generates Ed25519 keypair                                   │
│   2. Device registers → Identity Service creates DID on-chain           │
│   3. Device receives DID + Verifiable Credential (JWT)                  │
│   4. Verifier resolves issuer DID from blockchain                       │
│   5. Verifier checks signature + revocation bitmap                      │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
iota-identity-iot/
├── identity-service/      # Core backend service (Rust + Axum)
│   └── src/
│       ├── api/           # REST API endpoints
│       ├── cache/         # DID/Credential caching (Moka)
│       ├── credential/    # Verifiable Credential issuance
│       ├── did/           # DID lifecycle management
│       └── revocation/    # RevocationBitmap2022 on-chain
│
├── device-client/         # IoT device CLI (Rust)
│   └── src/
│       ├── identity/      # Device identity management
│       ├── registration/  # Device registration flow
│       ├── tls/           # TLS + DID authentication
│       └── storage/       # Persistent credential storage
│
├── shared/                # Common types and utilities
│   └── src/
│       ├── config.rs      # Network configuration
│       ├── types.rs       # Shared data structures
│       └── error.rs       # Error types
│
├── benchmarks/            # Performance benchmarking suite
├── tools/                 # Utility scripts
│   ├── accumulate_tokens.py    # Testnet faucet automation
│   ├── derive_address.py       # Address derivation utility
│   ├── parallel_benchmark.py   # Scalability testing
│   └── run_benchmarks.sh       # Benchmark runner
│
└── test-scripts/          # Manual and automated tests
    └── MANUAL_TESTS.md    # Comprehensive test guide
```

## Quick Start

### Prerequisites

- Rust 1.75+ (`rustup update stable`)
- Python 3.10+ (for utility scripts)
- `jq` and `curl` (for testing)

### 1. Clone and Build

```bash
git clone https://github.com/Forg-dev/iota-identity-iot.git
cd iota-identity-iot
cargo build --release
```

### 2. Start the Identity Service

```bash
# Set environment variables
export IOTA_IDENTITY_PKG_ID=0x222741bbdff74b42df48a7b4733185e9b24becb8ccfbafe8eac864ab4e4cc555
export IOTA_NETWORK=testnet

# Run the service
./target/release/identity-service
```

Wait for: `Server running at http://0.0.0.0:8080`

### 3. Initialize the Issuer (first time only)

```bash
# Check issuer status
curl -s http://localhost:8080/api/v1/issuer/status | jq .

# If not initialized, create issuer DID on-chain
curl -s -X POST http://localhost:8080/api/v1/issuer/initialize | jq .
```

### 4. Register a Device

```bash
# Using the device-client CLI
./target/release/device-client \
    --identity-service http://localhost:8080 \
    --data-dir ./my-device \
    register \
    --device-type sensor \
    --capabilities "temperature,humidity"
```

### 5. Verify Device Identity

```bash
# The device now has:
# - DID: ./my-device/identity.json
# - Credential: ./my-device/credential.jwt
# - Private key: ./my-device/private_key.hex

# Verify the credential
cat ./my-device/credential.jwt | \
  curl -s -X POST http://localhost:8080/api/v1/credential/verify \
    -H "Content-Type: application/json" \
    -d "{\"credential_jwt\": \"$(cat)\"}" | jq .
```

## API Reference

### Core Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Service health check |
| `/metrics` | GET | Cache and system metrics |
| `/api/v1/issuer/status` | GET | Issuer initialization status |
| `/api/v1/issuer/initialize` | POST | Initialize issuer DID on-chain |
| `/api/v1/device/register` | POST | Register new device (creates DID + credential) |
| `/api/v1/did/resolve/:did` | GET | Resolve DID to DID Document |
| `/api/v1/credential/verify` | POST | Verify a Verifiable Credential |
| `/api/v1/credential/revoke-onchain` | POST | Revoke credential (RevocationBitmap2022) |

### Example: Device Registration

```bash
curl -X POST http://localhost:8080/api/v1/device/register \
  -H "Content-Type: application/json" \
  -d '{
    "public_key": "a1b2c3d4e5f6...",
    "device_type": "sensor",
    "capabilities": ["temperature"]
  }'
```

Response:
```json
{
  "did": "did:iota:testnet:0x1234...",
  "object_id": "0x1234...",
  "credential_jwt": "eyJhbGciOiJFZERTQSI...",
  "credential_expires_at": "2027-02-03T..."
}
```

### Example: Credential Revocation

```bash
curl -X POST http://localhost:8080/api/v1/credential/revoke-onchain \
  -H "Content-Type: application/json" \
  -d '{
    "credential_id": "urn:uuid:12345...",
    "revocation_index": 0
  }'
```

## TLS Authentication

The system supports mutual TLS (mTLS) authentication using DID-based credentials:

```bash
# Terminal 1: Start TLS server
./target/release/device-client \
    --identity-service http://localhost:8080 \
    --data-dir ./server-device \
    serve --port 8443

# Terminal 2: Connect as client
./target/release/device-client \
    --identity-service http://localhost:8080 \
    --data-dir ./client-device \
    connect --addr localhost:8443
```

### Authentication Flow

1. TLS 1.3 handshake establishes encrypted channel
2. Client sends: DID, JWT credential, public key, challenge
3. Server verifies JWT signature against issuer's on-chain public key
4. Server checks RevocationBitmap2022 for revocation status
5. Mutual challenge-response proves key ownership
6. Authenticated channel established (~127ms total)

## Benchmarking

### Run Standard Benchmarks

```bash
# Start identity service first, then:
./tools/run_benchmarks.sh --iterations 10
```

### Run Scalability Tests

```bash
# Test parallel device registration
python3 tools/parallel_benchmark.py --devices 100 --concurrency 10
```

### Results (Testnet)

| Benchmark | Mean | P95 | P99 |
|-----------|------|-----|-----|
| DID Resolution (Cached) | 0.13ms | 0.24ms | 0.24ms |
| Credential Verification | 0.24ms | 0.38ms | 0.38ms |
| Revocation Check | 0.13ms | 0.18ms | 0.18ms |
| DID Resolution (Cold) | 74.85ms | 149.12ms | 149.12ms |
| DID Creation | 1010ms | 1214ms | 1214ms |
| Device Registration | 934ms | 943ms | 943ms |

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `IOTA_NETWORK` | `testnet` | Network: testnet, devnet, mainnet |
| `IOTA_IDENTITY_PKG_ID` | (required) | Identity package ID on IOTA |
| `RUST_LOG` | `info` | Log level |

### Supported Networks

| Network | RPC Endpoint | Faucet |
|---------|--------------|--------|
| testnet | https://api.testnet.iota.cafe | https://faucet.testnet.iota.cafe |
| devnet | https://api.devnet.iota.cafe | https://faucet.devnet.iota.cafe |
| mainnet | https://api.mainnet.iota.cafe | N/A |

### Pre-funding for Benchmarks

```bash
# Derive your issuer's wallet address
python3 tools/derive_address.py

# Accumulate testnet tokens
python3 tools/accumulate_tokens.py --target 100
```

## Persistence

The system persists issuer identity to survive restarts:

```
~/.iota-identity-service/
└── issuer_identity.json
    ├── did                          # Issuer's DID
    ├── signing_key_hex              # Key for signing credentials
    ├── tx_key_hex                   # Key for blockchain transactions
    ├── verification_method_fragment # DID Document reference
    └── created_at                   # Initialization timestamp
```

Device identities are stored in the specified `--data-dir`:

```
./my-device/
├── identity.json      # Device DID and metadata
├── credential.jwt     # Verifiable Credential
└── private_key.hex    # Device's Ed25519 private key
```

## Testing

### Manual Tests

See [test-scripts/MANUAL_TESTS.md](test-scripts/MANUAL_TESTS.md) for comprehensive testing guide covering:

- Service health and metrics
- DID lifecycle (create, resolve, rotate, deactivate)
- Credential issuance and verification
- On-chain revocation
- TLS authentication
- Persistence across restarts

### Quick Verification

```bash
# Health check
curl -s http://localhost:8080/health | jq .

# Metrics
curl -s http://localhost:8080/metrics | jq .

# Issuer status
curl -s http://localhost:8080/api/v1/issuer/status | jq .
```

## Comparison with Traditional PKI

| Aspect | This System | Traditional PKI |
|--------|-------------|-----------------|
| Trust Anchor | Blockchain consensus | Certificate Authority |
| Single Point of Failure | No | Yes (CA) |
| Revocation Check | 0.13ms (local bitmap) | 19-291ms (OCSP) |
| Offline Verification | Yes (cached DID) | No (requires OCSP) |
| Privacy | Preserved | CA sees all requests |
| Scalability | Decentralized | Centralized bottleneck |

## Documentation

- [MANUAL_TESTS.md](test-scripts/MANUAL_TESTS.md) - Complete testing guide
- [SYSTEM_DOCUMENTATION.md](SYSTEM_DOCUMENTATION.md) - Technical architecture
- [PRESENTATION_GUIDE.md](PRESENTATION_GUIDE.md) - Thesis presentation guide
- [API_REFERENCE.md](API_REFERENCE.md) - API documentation

## Technology Stack

- **Language**: Rust 1.75+
- **Web Framework**: Axum 0.8
- **Blockchain**: IOTA Rebased (Move-based)
- **Identity**: IOTA Identity SDK
- **Cryptography**: Ed25519 (RFC 8032)
- **Caching**: Moka
- **TLS**: rustls + tokio-rustls
- **Standards**: W3C DID v1.0, W3C VC v2.0, RevocationBitmap2022

## License

MIT License - See [LICENSE](LICENSE) for details.

## References

1. W3C. "Decentralized Identifiers (DIDs) v1.0" (2022)
2. W3C. "Verifiable Credentials Data Model v2.0" (2024)
3. IOTA Foundation. "IOTA DID Method Specification v2.0"
4. DIF. "RevocationBitmap2022 Status Method"
5. Bernstein et al. "Ed25519: High-speed signatures" (2012)

---

*Developed as part of a thesis project on decentralized identity for IoT*