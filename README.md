# IOTA Identity for IoT

A decentralized Public Key Infrastructure (PKI) system for Internet of Things devices, built on IOTA Rebased blockchain. This project explores how Decentralized Identifiers (DIDs) and Verifiable Credentials can replace traditional Certificate Authorities for authenticating IoT devices.

## About This Project

This is a thesis project investigating whether blockchain-based identity management can offer practical advantages over traditional PKI in IoT contexts. The main questions we're trying to answer:

- Can we achieve equivalent security without relying on Certificate Authorities?
- Is revocation checking faster with an on-chain bitmap compared to OCSP/CRL?
- Can devices verify each other's identities offline (with cached data)?
- What are the trade-offs in terms of latency, scalability, and complexity?

The system is fully functional on IOTA's testnet and demonstrates the complete lifecycle: device registration, credential issuance, mutual TLS authentication, and credential revocation.

## What's Implemented

The project consists of two main components:

**Identity Service** - A backend server that acts as the credential issuer. It creates DIDs on the blockchain, issues JWT-based Verifiable Credentials, and manages revocation through an on-chain bitmap (RevocationBitmap2022).

**Device Client** - A command-line tool that simulates an IoT device. It can register with the Identity Service, store its credentials locally, and establish TLS connections with other devices using DID-based mutual authentication.

Both components are complete and tested. The only remaining work is the benchmarking suite for collecting performance data.

## Architecture

```
                         IOTA Rebased Testnet
                        (api.testnet.iota.cafe)
    ┌──────────────────────────────────────────────────────────┐
    │  Identity Package (Move Smart Contract)                   │
    │  - DID Documents stored as on-chain objects               │
    │  - RevocationBitmap2022 embedded in service endpoints     │
    └──────────────────────────────────────────────────────────┘
                                 │
                                 │ IOTA SDK
                                 ▼
    ┌──────────────────────────────────────────────────────────┐
    │                    Identity Service                       │
    │                                                           │
    │  DID Manager         Credential Issuer    Revocation Mgr  │
    │  - Create/Resolve    - Issue JWTs         - Revoke        │
    │  - Rotate keys       - Verify             - Check status  │
    │  - Deactivate        - Ed25519 signing    - Roaring bitmap│
    │                                                           │
    │  Cache (L1+L2)                     REST API (Axum)        │
    └──────────────────────────────────────────────────────────┘
                                 │
                                 │ HTTP
                                 ▼
    ┌──────────────────────────────────────────────────────────┐
    │                     Device Client                         │
    │                                                           │
    │  Identity Manager    Secure Storage       TLS Module      │
    │  - Load/save         - Private key        - Client/Server │
    │  - Sign challenges   - Credentials        - Verification  │
    │                                                           │
    │  Registrar                          DID Resolver + Cache  │
    └──────────────────────────────────────────────────────────┘
```

## Project Structure

```
iota-identity-iot/
├── Cargo.toml                 # Workspace configuration
├── README.md
├── MANUAL_TESTS.md            # Testing guide
│
├── shared/                    # Common library
│   └── src/
│       ├── config.rs          # Network, timeouts, paths
│       ├── error.rs           # Error types
│       └── types.rs           # DID, Credential, API types
│
├── identity-service/          # Backend (the Issuer)
│   └── src/
│       ├── main.rs            # Server entry point
│       ├── api/mod.rs         # REST endpoints
│       ├── did/mod.rs         # DID operations
│       ├── credential/mod.rs  # Credential issuance
│       ├── revocation/bitmap.rs
│       └── cache/mod.rs
│
├── device-client/             # IoT device simulator
│   └── src/
│       ├── main.rs            # CLI
│       ├── identity/mod.rs
│       ├── storage/mod.rs
│       ├── registration/mod.rs
│       ├── resolver/mod.rs
│       └── tls/
│           ├── mod.rs         # TLS client and server
│           └── verifier.rs    # Credential verification
│
└── benchmarks/                # Performance tests (planned)
```

## Getting Started

### Prerequisites

You'll need Rust 1.75 or later and an internet connection to reach the IOTA testnet.

### Building

```bash
cd iota-identity-iot
cargo build --release
```

### Running the Identity Service

```bash
export STRONGHOLD_PASSWORD="your-password-here"
cargo run --release --package identity-service
```

On first run, the service creates an Issuer DID on the blockchain. This takes about 7 seconds. After that, you'll see:

```
INFO Server running at http://0.0.0.0:8080
```

### Registering a Device

You can register a device either through the API or using the CLI.

**Using the API:**

```bash
PUBLIC_KEY=$(openssl rand -hex 32)

curl -s -X POST http://localhost:8080/api/v1/device/register \
  -H "Content-Type: application/json" \
  -d "{
    \"public_key\": \"$PUBLIC_KEY\",
    \"device_type\": \"sensor\",
    \"capabilities\": [\"temperature\"]
  }" | jq .
```

**Using the CLI:**

```bash
./target/release/device-client \
    --data-dir ./my-device \
    register \
    --device-type sensor \
    --capabilities "temperature,humidity"
```

The device receives a DID and a Verifiable Credential (JWT), which it stores locally.

### Testing TLS Authentication

This requires three terminal windows.

**Terminal 1** - Keep the Identity Service running.

**Terminal 2** - Register and start a server device:

```bash
./target/release/device-client --data-dir ./server-device register -t gateway
./target/release/device-client --data-dir ./server-device server -p 8443
```

**Terminal 3** - Register and connect a client device:

```bash
./target/release/device-client --data-dir ./client-device register -t sensor
./target/release/device-client --data-dir ./client-device connect -a localhost:8443
```

If everything works, you'll see the authentication metrics:

```
Connected and authenticated!
  Peer DID: did:iota:testnet:0x...

  Metrics:
    TLS Handshake: 45ms
    DID Auth: 120ms
    Credential Verify: 80ms
    Challenge-Response: 2ms
    Total: 167ms
```

## API Overview

The Identity Service exposes these endpoints:

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check |
| `POST /api/v1/device/register` | Register a device (creates DID + credential) |
| `GET /api/v1/did/resolve/:did` | Resolve a DID to its document |
| `POST /api/v1/did/rotate-key/:did` | Rotate a DID's verification key |
| `POST /api/v1/did/deactivate/:did` | Deactivate a DID |
| `POST /api/v1/credential/verify` | Verify a credential JWT |
| `POST /api/v1/credential/revoke-onchain` | Revoke a credential |
| `GET /api/v1/credential/status-onchain/:index` | Check revocation status |

See MANUAL_TESTS.md for detailed examples of each endpoint.

## Device Client Commands

```
device-client [OPTIONS] <COMMAND>

Commands:
  register    Register with the Identity Service
  reregister  Create a new identity (replaces existing)
  show        Display current identity
  sign        Sign a message
  resolve     Resolve a DID
  server      Start a TLS server
  connect     Connect to another device
  clear       Delete stored data

Options:
  --identity-service <URL>   [default: http://localhost:8080]
  --data-dir <PATH>          [default: ./device-data]
```

## Performance

These are rough numbers from testing on the IOTA testnet:

| Operation | Time |
|-----------|------|
| DID Creation | ~7 seconds (blockchain transaction) |
| DID Resolution (first time) | ~150-200ms |
| DID Resolution (cached) | <1ms |
| Credential Verification | <5ms |
| Revocation Check | <1ms (bitmap lookup) |
| Full TLS + DID Auth | ~150-250ms |

The main advantage over traditional PKI is in revocation checking. OCSP typically adds 50-200ms of latency per check, while our bitmap lookup is essentially instant once the issuer's DID document is cached.

## Security

The system uses Ed25519 for all signatures, TLS 1.3 for transport encryption, and JWTs for credential encoding.

The trust model differs from traditional PKI: instead of trusting a Certificate Authority, verifiers trust the IOTA blockchain consensus. The Issuer (Identity Service) must still be trusted to issue credentials correctly, but verification can happen without contacting the Issuer.

## Testing

MANUAL_TESTS.md contains a comprehensive guide with nine sections covering:

- Basic service health checks
- DID lifecycle (create, resolve, rotate, deactivate)
- Credential issuance and verification
- On-chain revocation
- Device Client CLI operations
- Persistence tests
- Input validation
- TLS with DID authentication

## References

- [W3C DID Core](https://www.w3.org/TR/did-core/)
- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/)
- [IOTA Identity Documentation](https://wiki.iota.org/identity.rs/introduction)
- [IOTA Rebased](https://docs.iota.org/)

## License

MIT
