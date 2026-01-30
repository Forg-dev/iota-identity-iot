# Project Tree - IOTA Identity for IoT

```
iota-identity-iot/
│
├── Cargo.toml                          # Workspace root with all dependencies
├── README.md                           # Project documentation
│
├── shared/                             # FASE 1: Shared Module
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs                      # Crate entry point
│       ├── config.rs                   # Configuration (networks, paths)
│       ├── constants.rs                # IOTA endpoints, Package IDs, TTLs
│       ├── error.rs                    # IdentityError enum
│       └── types.rs                    # DeviceIdentity, Credential, etc.
│
├── identity-service/                   # FASE 2: Identity Service (Backend)
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs                     # Service entry point (Axum server)
│       ├── lib.rs                      # Crate entry + AppState
│       ├── api/
│       │   └── mod.rs                  # REST API handlers
│       │                               #   POST /api/v1/device/register
│       │                               #   GET  /api/v1/did/resolve/:did
│       │                               #   POST /api/v1/credential/verify
│       ├── cache/
│       │   └── mod.rs                  # Multi-level caching (Moka)
│       │                               #   - DID Document cache (24h TTL)
│       │                               #   - Credential cache (12h TTL)
│       ├── credential/
│       │   └── mod.rs                  # W3C Verifiable Credentials
│       │                               #   - issue_credential()
│       │                               #   - verify_credential()
│       │                               #   - JWT encoding
│       └── did/
│           └── mod.rs                  # IOTA Rebased DID Manager
│                                       #   - create_did() → publish to blockchain
│                                       #   - resolve_did() → query blockchain
│                                       #   - Uses IdentityClientReadOnly
│
├── device-client/                      # FASE 3 & 4: Device Client
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs                     # CLI entry point
│       │                               #   device-client register
│       │                               #   device-client connect
│       │                               #   device-client server
│       ├── lib.rs                      # Crate entry + re-exports
│       ├── registration/
│       │   └── mod.rs                  # Device registration
│       │                               #   - Generate Ed25519 keypair
│       │                               #   - Call Identity Service API
│       │                               #   - Store DID + credential
│       ├── resolver/
│       │   └── mod.rs                  # DID Resolution
│       │                               #   - Query IOTA Rebased blockchain
│       │                               #   - Local cache with TTL
│       │                               #   - Fallback to Identity Service
│       ├── storage/
│       │   └── mod.rs                  # Secure Storage
│       │                               #   - Stronghold integration
│       │                               #   - Encrypted credential storage
│       └── tls/
│           └── mod.rs                  # TLS + DID Authentication
│                                       #   - TlsClient: connect with auth
│                                       #   - TlsServer: accept with auth
│                                       #   - DID auth protocol post-handshake
│
├── docs/                               # Documentation
│   └── (thesis documentation)
│
├── examples/                           # FASE 5: Examples & Benchmarks
│   └── (simulation examples)
│
├── benches/                            # Benchmarks
│   └── (criterion benchmarks)
│
└── scripts/                            # Utility scripts
    └── (setup, testing scripts)
```