# IOTA Identity IoT — Complete System Documentation

## Decentralized Authentication System for IoT Using IOTA Rebased as a Trust Anchor

---

## Table of Contents

1. [Introduction and Motivation](#1-introduction-and-motivation)
2. [System Architecture Overview](#2-system-architecture-overview)
3. [Core Concepts and Standards](#3-core-concepts-and-standards)
4. [The Shared Library (`shared`)](#4-the-shared-library-shared)
5. [The Identity Service (`identity-service`)](#5-the-identity-service-identity-service)
6. [The Device Client (`device-client`)](#6-the-device-client-device-client)
7. [The Benchmark Suite (`benchmarks`)](#7-the-benchmark-suite-benchmarks)
8. [Operational Flows](#8-operational-flows)
9. [Security Model](#9-security-model)
10. [Performance Analysis](#10-performance-analysis)
11. [Persistence and Data Management](#11-persistence-and-data-management)
12. [Configuration Reference](#12-configuration-reference)
13. [Technology Stack](#13-technology-stack)

---

## 1. Introduction and Motivation

Traditional Public Key Infrastructure (PKI) relies on centralized Certificate Authorities (CAs) to issue, validate, and revoke digital certificates. While this model has served the web for decades, it introduces a single point of failure, creates privacy concerns (CAs can observe all validation requests), and depends on fragile revocation mechanisms like OCSP (Online Certificate Status Protocol) that add latency and can fail silently. In the Internet of Things (IoT) domain, these shortcomings are amplified: billions of constrained devices must authenticate to one another reliably, quickly, and without depending on the availability of any centralized server.

This project replaces the entire CA-based trust model with a decentralized alternative built on top of **IOTA Rebased**, a Move-based distributed ledger. Instead of X.509 certificates, devices receive **W3C Decentralized Identifiers (DIDs)** whose documents are stored immutably on the blockchain. Instead of CA-signed certificates, devices receive **W3C Verifiable Credentials (VCs)** signed by a trusted issuer whose public key can be resolved from the ledger by any party. Instead of OCSP for revocation, the system employs **RevocationBitmap2022**, a compact bitmap embedded in the issuer's on-chain DID Document that any verifier can read locally.

The result is a fully functional, end-to-end decentralized identity and authentication system for IoT devices — from device registration to mutual TLS authentication between two devices — implemented entirely in Rust.

---

## 2. System Architecture Overview

The system is composed of three principal runtime components and one shared library, all organized as a Cargo workspace with four member crates:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         SYSTEM ARCHITECTURE                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   IoT Device                  Identity Service              Blockchain  │
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
└─────────────────────────────────────────────────────────────────────────┘
```

**Identity Service** — A backend HTTP server (Axum) that acts as the trusted issuer. It creates DIDs on the IOTA Rebased blockchain, issues W3C Verifiable Credentials to devices, manages revocation bitmaps, and exposes a REST API for all identity lifecycle operations.

**Device Client** — A CLI application that represents an individual IoT device. It generates its own Ed25519 key pair, registers with the Identity Service to obtain a DID and a Verifiable Credential, stores its identity locally, and can establish mutually authenticated TLS connections with other devices using DID-based authentication.

**IOTA Rebased Blockchain** — The decentralized trust anchor. DID Documents are published as Move objects on the ledger, making them tamper-proof and globally resolvable. The revocation bitmap is stored as a service endpoint inside the issuer's DID Document, so any party can verify the revocation status of any credential without contacting the issuer.

**Shared Library** — Common types, configuration structures, error definitions, and constants used by all other crates, ensuring consistency across the system.

---

## 3. Core Concepts and Standards

### 3.1 Decentralized Identifiers (DIDs)

A DID is a globally unique identifier that does not require a centralized registration authority. In this system, DIDs follow the IOTA DID Method and have the form:

```
did:iota:<network>:<hex-address>
```

For example: `did:iota:testnet:0x1234abcd...`

Each DID is backed by a **DID Document** stored on the IOTA Rebased blockchain. The DID Document contains the subject's public key(s) as verification methods, service endpoints (including the revocation bitmap), and authentication references. Because it lives on a distributed ledger, any party can resolve a DID to its document without trusting an intermediary.

### 3.2 Verifiable Credentials (VCs)

A Verifiable Credential is a tamper-evident digital assertion issued by a trusted party. This system follows the W3C Verifiable Credentials Data Model and issues credentials of type `IoTDeviceCredential`. Each credential contains:

- **Issuer DID** — the DID of the Identity Service that signed the credential
- **Subject DID** — the DID of the device being credentialed
- **Credential Subject** — metadata including device type and capabilities
- **Issuance and Expiration dates** — temporal validity bounds
- **Credential Status** — a `RevocationBitmap2022` reference with the credential's revocation index
- **Proof** — an Ed25519Signature2020 over the canonical JSON serialization

Credentials are also issued in **JWT (JSON Web Token)** compact format using the EdDSA algorithm, enabling efficient transmission and standard JWT parsing.

### 3.3 RevocationBitmap2022

RevocationBitmap2022 is a W3C-aligned revocation mechanism where a bitmap is encoded as a service endpoint in the issuer's DID Document. Each credential is assigned a unique index in the bitmap. When a credential is revoked, its corresponding bit is set to 1. The bitmap is serialized as a Roaring Bitmap, compressed with zlib, Base64-encoded, and stored as a data URL:

```
data:application/octet-stream;base64,<zlib-compressed-roaring-bitmap>
```

This approach has several advantages over OCSP:
- **No network dependency at verification time** — once the issuer's DID Document is cached, revocation checks are local
- **Constant-time lookup** — checking a single bit in a bitmap is O(1)
- **Privacy-preserving** — verifiers do not reveal which credentials they are checking
- **Persistent** — the bitmap survives issuer restarts because it is stored on-chain

### 3.4 Ed25519 Cryptography

All cryptographic operations in the system use Ed25519 (RFC 8032) via the `ed25519-dalek` library. Ed25519 was chosen for its security properties (128-bit security level), small key and signature sizes (32 bytes and 64 bytes respectively), deterministic signatures, and fast verification — all properties well-suited to resource-constrained IoT environments.

---

## 4. The Shared Library (`shared`)

The `shared` crate provides the common vocabulary and infrastructure that all other crates depend upon. It ensures that all components share the same type definitions, configuration structures, error taxonomy, and network constants.

### 4.1 Configuration (`config.rs`)

The configuration module defines a layered hierarchy of typed settings that can be loaded from environment variables.

**`IotaNetwork`** is an enumeration of the four supported IOTA Rebased networks: `Testnet`, `Devnet`, `Mainnet`, and `Local`. Each variant knows its own RPC endpoint and faucet URL. For instance, Testnet connects to `https://api.testnet.iota.cafe` and its faucet lives at `https://faucet.testnet.iota.cafe/gas`. The Local variant points to `http://127.0.0.1:9000` for development with a local node.

**`IdentityServiceConfig`** is the top-level configuration for the backend service. It aggregates sub-configurations for the API server (`ApiConfig`), the cache layer (`CacheConfig`), the storage backend (`StorageConfig`), and the credential issuance policy (`CredentialConfig`). The `from_env()` constructor reads environment variables (such as `IOTA_NETWORK`, `IOTA_IDENTITY_PKG_ID`) and falls back to sensible defaults. A `validate()` method ensures that required fields like the Identity Package ID are present.

**`ApiConfig`** controls the HTTP listener with fields for host, port, CORS policy, maximum request body size (default 1 MB), and request timeout.

**`CacheConfig`** defines the time-to-live for cached DID Documents (default 24 hours) and credentials (default 12 hours), as well as maximum cache sizes (100,000 DID Documents and 500,000 credentials).

**`CredentialConfig`** specifies the validity period for issued credentials (default 365 days) and the issuer name.

**`DeviceClientConfig`** packages the settings needed by a device: the Identity Service URL, the IOTA network to use, storage paths, TLS parameters, and local cache settings.

**`TlsConfig`** controls TLS behavior including handshake timeouts, authentication timeouts, certificate validity periods, and whether to verify revocation status during TLS authentication.

### 4.2 Constants (`constants.rs`)

This module centralizes all magic values and well-known identifiers used across the system:

- **Network endpoints** for Testnet, Devnet, Mainnet, and Local
- **Identity Package IDs** — the hex addresses of the deployed IOTA Identity Move packages on each network (e.g., `0x222741bbdff74b42df48a7b4733185e9b24becb8ccfbafe8eac864ab4e4cc555` on Testnet)
- **Faucet URLs** for obtaining test tokens
- **Gas budgets** for each blockchain operation: 50,000,000 for DID publication, 30,000,000 for DID updates, 20,000,000 for deactivation, and 25,000,000 for revocation operations
- **Cache parameters**: 86,400 seconds (24 hours) TTL for DIDs, 43,200 seconds (12 hours) for credentials
- **Credential constants**: W3C context URLs, credential type names, default validity of 31,536,000 seconds (365 days)
- **TLS constants**: 90-day certificate validity, 30-second handshake timeout, 60-second auth timeout
- **API settings**: default port 8080, 1 MB maximum body size

### 4.3 Error Handling (`error.rs`)

The `IdentityError` enumeration provides a comprehensive, categorized error taxonomy using the `thiserror` derive macro. Errors are organized into logical domains:

**DID Errors** cover DID creation failures, resolution failures, invalid DID format, DID-not-found, DID-already-deactivated, and DID update errors. Each variant carries context strings that explain what went wrong and which DID was involved.

**Credential Errors** include issuance failures, verification failures, expiration (with the expiration timestamp), revocation (with credential ID and reason), and generic invalid-credential conditions.

**Cryptography Errors** handle key generation failures, invalid public keys, invalid signatures, and signing operation errors.

**Network Errors** wrap connection failures (with endpoint and reason), transaction failures, gas-related problems (insufficient gas, faucet failures), and general timeout conditions.

**Storage Errors** cover Stronghold failures, encryption problems, I/O errors, and missing environment variables.

**TLS Errors** address handshake failures, certificate problems, DID-based authentication failures, and connection timeouts with the specified timeout duration.

**API Errors** handle invalid requests, registration problems, and unauthorized operations.

Every error variant implements `Display` via `thiserror` for human-readable messages. The `category()` method classifies errors into broad categories (did, credential, crypto, network, storage, tls, api, config, internal) for metrics collection. The `is_retryable()` method indicates whether the error is transient and the operation could succeed if retried — for instance, network connection errors and gas faucet errors are retryable, but invalid DIDs are not.

### 4.4 Type Definitions (`types.rs`)

This module defines all the data structures that flow between components:

**`DeviceIdentity`** represents a device's identity with fields for a UUID, the DID string, the blockchain object ID, the public key in hex, the device type, capabilities, creation and update timestamps, and a status field. The `new()` constructor generates a fresh UUID and sets timestamps automatically.

**`DeviceType`** is an enumeration with six variants: `Sensor`, `Gateway`, `Actuator`, `Controller`, `Edge`, and `Generic`. It serializes to lowercase strings for JSON compatibility.

**`DeviceStatus`** tracks the lifecycle of a device with variants `Active`, `Suspended`, `Revoked`, and `Pending`.

**`DeviceCredential`** is the full W3C Verifiable Credential structure. It carries the credential ID (a `urn:uuid:` URI), JSON-LD context URLs, credential types, the issuer DID, issuance and expiration dates, the credential subject, an optional credential status (for revocation), and an optional proof. The `is_expired()` method compares the expiration date against the current UTC time. The `time_until_expiration()` method returns a `chrono::Duration` representing the remaining validity.

**`CredentialStatus`** references the RevocationBitmap2022 service with three fields: the service ID (e.g., `did:iota:testnet:0x...#revocation`), the status type (always `RevocationBitmap2022`), and the revocation bitmap index as a string.

**`CredentialSubject`** describes the credentialed entity with the subject's DID, device type, capabilities list, and optional manufacturer, model, and firmware version fields.

**`CredentialProof`** carries the cryptographic proof: proof type (`Ed25519Signature2020`), creation timestamp, verification method reference, proof purpose (`assertionMethod`), and the Base64-encoded signature value.

**`SimplifiedDIDDocument`** is a cache-friendly representation of a DID Document with the DID string, a list of verification methods, optional authentication references, optional services, and an update timestamp. This is the type that gets cached and transmitted between components rather than the full IOTA SDK document type.

**API Request and Response types** form the contract between the Device Client and the Identity Service. `DeviceRegistrationRequest` carries the public key, device type, capabilities, and optional manufacturer/model fields. `DeviceRegistrationResponse` returns the assigned DID, blockchain object ID, the issued credential JWT, and the credential's expiration date. Similar request/response pairs exist for credential verification, revocation (both in-memory and on-chain), key rotation, DID deactivation, and DID resolution.

**`DIDAuthMessage`** is the protocol message used during TLS-based DID authentication. It carries a message type (Hello, Challenge, Response, Success, or Failure), the sender's DID, their credential JWT, an optional challenge, an optional challenge response, an optional public key, and a timestamp.

**Metrics types** include `OperationMetrics` for individual operation timing and `AggregatedMetrics` for summary statistics including throughput, mean and median latencies, percentiles, and cache hit rate.

---

## 5. The Identity Service (`identity-service`)

The Identity Service is the central backend component. It runs as an HTTP server and orchestrates all identity lifecycle operations: creating DIDs on the blockchain, issuing Verifiable Credentials, managing revocation bitmaps, and serving DID resolution requests with caching.

### 5.1 Application Bootstrap (`main.rs`)

When the service starts, it performs the following initialization sequence:

1. **Logging** — Configures structured logging via `tracing-subscriber` with INFO level, thread IDs, and target module names.

2. **Configuration** — Loads `IdentityServiceConfig` from environment variables and validates that all required fields are present.

3. **Issuer Storage Path** — Determines the path for persisting the issuer's identity, defaulting to `~/.iota-identity-service/`.

4. **DID Manager** — Initializes a `DIDManager` that connects to the IOTA Rebased network, builds an identity client, and optionally requests funds from the faucet on Testnet/Devnet.

5. **Cache Manager** — Creates a `CacheManager` with Moka in-memory caches configured per the cache settings.

6. **Revocation Manager** — Initializes the in-memory `RevocationManager` for session-based revocation tracking.

7. **On-Chain Revocation Manager** — Creates an `OnChainRevocationManager` with a placeholder issuer DID. This will be updated when the issuer is initialized on-chain.

8. **Credential Issuer** — Constructs the `CredentialIssuer` which either loads a previously persisted issuer identity (including signing key, transaction key, and DID) or generates a fresh Ed25519 signing key. If a persisted identity is found, the DID Manager's control info is restored so the service can continue modifying the issuer's DID Document after a restart.

9. **Application State** — All components are wrapped in `Arc` and assembled into a shared `AppState` structure.

10. **HTTP Server** — An Axum router is created with all API routes, CORS middleware, and the shared state. The server binds to the configured address (default `0.0.0.0:8080`) and begins accepting requests.

### 5.2 REST API Endpoints (`api/mod.rs`)

The API module defines the complete set of HTTP endpoints and their handler functions:

**`GET /health`** returns a simple JSON response with the service status and version. This endpoint is used by the benchmark suite and monitoring tools to verify that the service is running.

**`POST /api/v1/issuer/initialize`** creates the issuer's DID on the IOTA Rebased blockchain. This is the first operation that must be performed after starting the service for the first time. The handler retrieves the Credential Issuer's public key, calls `DIDManager::create_issuer_did_with_key()` to publish a DID Document on-chain, then adds a RevocationBitmap2022 service endpoint to the DID Document. The issuer identity — including the DID, signing key, transaction key, and verification method fragment — is persisted to disk so the issuer survives restarts. If the issuer is already initialized, the endpoint returns the existing DID without creating a new one.

**`GET /api/v1/issuer/status`** returns the current state of the issuer: the DID, whether it is initialized on-chain, whether the service has control over it (can modify its DID Document), and revocation bitmap statistics including the total number of credentials issued, the number revoked, and whether there are unpublished changes.

**`POST /api/v1/device/register`** is the primary endpoint for IoT device onboarding. When a device submits its public key (64 hex characters representing 32 bytes), device type, and capabilities, the handler performs two operations in sequence. First, it calls `DIDManager::create_did()` which publishes a new DID Document on the IOTA Rebased blockchain containing the device's public key as a verification method. Second, it calls `CredentialIssuer::issue_credential_jwt()` which creates a W3C Verifiable Credential in JWT format, signed by the issuer's Ed25519 key, with a credential status referencing the RevocationBitmap2022 at the next available index. The response returns the newly created DID, the blockchain object ID, the signed JWT credential, and the credential's expiration date. The public key length is validated at 64 hex characters; invalid lengths are rejected with a 400 Bad Request.

**`GET /api/v1/did/resolve/{did}`** resolves a DID to its DID Document. The handler first URL-decodes the DID parameter, then checks the Moka cache for a previously resolved document. On a cache hit, the cached document is returned immediately with a `from_cache: true` flag and sub-millisecond resolution time. On a cache miss, the DID is resolved from the IOTA Rebased blockchain via `DIDManager::resolve_did()`, converted to a `SimplifiedDIDDocument` (extracting verification methods with multibase-encoded public keys, authentication references, and service endpoints), cached for future requests, and returned with the resolution time in milliseconds. The conversion logic handles JWK-format public keys from IOTA Identity by decoding the base64url `x` parameter and re-encoding as a base58-prefixed multibase string (prefix `z`).

**`POST /api/v1/credential/verify`** verifies a Verifiable Credential presented as a JWT. The handler splits the JWT into its three parts, Base64url-decodes the payload, extracts the `vc` (Verifiable Credential) claim, and deserializes it into a `DeviceCredential`. It first checks the in-memory revocation list; if the credential is revoked, it returns the revocation timestamp and reason. Otherwise, it delegates to `CredentialIssuer::verify_credential()` which checks expiration, on-chain revocation status via RevocationBitmap2022, proof existence, and signature validity. The response includes the validity status, subject DID, issuer DID, any error message, and the expiration date.

**`POST /api/v1/credential/revoke`** performs in-memory revocation. It accepts a credential ID and optional reason, marks the credential as revoked in the `RevocationManager`'s HashMap, and invalidates it from the credential cache. This revocation is session-scoped and will not survive a service restart.

**`GET /api/v1/credential/status/{credential_id}`** returns the revocation status of a credential from the in-memory revocation list, including whether it is revoked, the revocation timestamp, and the reason.

**`POST /api/v1/credential/revoke-onchain`** performs persistent on-chain revocation using RevocationBitmap2022. This is the preferred revocation method. The handler accepts a credential ID and a revocation index, sets the corresponding bit in the local Roaring Bitmap, and then, if the issuer's DID is initialized on-chain and the service has control, serializes the bitmap, compresses it with zlib, Base64-encodes it, and publishes the updated data URL as the revocation service endpoint in the issuer's DID Document via a blockchain transaction. The response indicates whether the on-chain publication succeeded. If the issuer DID is not yet initialized, the revocation is stored locally with a note that it has not been published on-chain.

**`GET /api/v1/credential/status-onchain/{index}`** checks the on-chain revocation status for a given bitmap index. It reads the local bitmap copy and returns whether the bit at that index is set.

**`GET /api/v1/revocation/bitmap-stats`** returns statistics about the revocation bitmap: the issuer DID, total credentials issued, number revoked, dirty flag (unpublished changes), and serialized size in bytes.

**`POST /api/v1/did/deactivate/{did}`** deactivates a DID on the blockchain. The handler verifies that the service has control over the DID (i.e., it was created by this service and the transaction key is available), then calls `DIDManager::deactivate_did()`. After successful deactivation, it invalidates the DID from the cache, creates an in-memory revocation entry, and if the credential has a known revocation index, also revokes it in the on-chain bitmap and publishes the updated bitmap.

**`POST /api/v1/did/rotate-key/{did}`** rotates the verification key for a DID. It accepts a new 64-character hex public key, verifies ownership of the DID, and calls `DIDManager::rotate_key()` which adds a new verification method to the DID Document on-chain. The old key remains in the document but the new key becomes the primary one. The DID Document cache is invalidated after rotation.

**`POST /api/v1/admin/cache/clear`** clears all in-memory caches (DID Documents and credentials). This is an administrative endpoint used primarily by the benchmark suite to ensure cold-cache measurements.

**`GET /metrics`** returns cache statistics (number of cached DIDs and credentials, whether caching is enabled) and network configuration.

The API module also defines an `ApiError` enum with variants `BadRequest`, `NotFound`, and `Internal`, along with automatic conversion from `IdentityError`. The `IntoResponse` implementation maps these to appropriate HTTP status codes (400, 404, 500) with JSON error bodies. Internal errors are logged but not leaked to the client.

### 5.3 DID Manager (`did/mod.rs`)

The DID Manager is the most complex component in the system, responsible for all interactions with the IOTA Rebased blockchain related to DID lifecycle management.

Upon initialization, it connects to the IOTA Rebased network by building an `IotaClient` via the SDK's `IotaClientBuilder`. On Testnet and Devnet, it automatically requests funds from the network faucet to pay for gas. It then creates a full `IdentityClient` (which can sign and submit transactions) backed by an in-memory JWK storage (`JwkMemStore` and `KeyIdMemstore`). This in-memory approach was chosen because Stronghold, IOTA's secure key storage, is not yet compatible with the Rebased SDK.

**DID Creation** (`create_did`) generates a new IOTA DID Document for a device. It takes the device's public key (hex-encoded Ed25519), device type, and capabilities. The process involves: (1) creating a new `IotaDocument` with the appropriate network name, (2) inserting a verification method with the device's public key using the JWK (JSON Web Key) format, (3) creating a `StorageSigner` to sign the publication transaction, (4) publishing the DID Document to the blockchain with the configured gas budget (50,000,000), and (5) recording the DID-to-control-info mapping so the service can later modify or deactivate this DID. The function returns a `DeviceIdentity` containing the new DID and its blockchain object ID.

**Issuer DID Creation** (`create_issuer_did_with_key`) is a specialized version that creates the issuer's DID. It follows the same flow but additionally generates a separate transaction key pair used for signing future blockchain transactions (DID updates, revocation bitmap updates). Both the signing key (used for credential signatures) and the transaction key (used for blockchain operations) are stored. The function returns a result struct containing the DID, the transaction key in hex, and the verification method fragment.

**DID Resolution** (`resolve_did`) retrieves a DID Document from the blockchain by parsing the DID string into an `IotaDID` and calling the identity client's `resolve_did` method. This is a read-only operation that does not require gas.

**Key Rotation** (`rotate_key`) adds a new verification method to an existing DID Document. It loads the current document from the blockchain, inserts a new verification method with the provided public key, and publishes the updated document. The operation requires the stored transaction key and costs 30,000,000 gas units.

**DID Deactivation** (`deactivate_did`) permanently deactivates a DID on the blockchain. After deactivation, the DID Document can no longer be updated and the DID is considered revoked. This operation costs 20,000,000 gas units.

**Revocation Service Update** (`update_revocation_service`) adds or updates the RevocationBitmap2022 service endpoint in a DID Document. It constructs a `Service` object with the type `RevocationBitmap2022` and the data URL containing the compressed bitmap, then publishes the updated document. This is called both during issuer initialization (to add the initial empty bitmap) and after each on-chain revocation (to update the bitmap).

**Control Info Restoration** (`restore_issuer_control_info`) is critical for service persistence. When the service restarts and loads the issuer identity from disk, it must rebuild the internal state that allows it to sign transactions for the issuer's DID. This function takes the persisted DID, transaction key hex, and verification method fragment, resolves the DID Document from the blockchain, reconstructs the `StorageSigner`, and re-inserts the control mapping. Without this, the service would lose the ability to modify the issuer's DID Document after a restart.

The DID Manager maintains two internal maps protected by `RwLock`:
- **`did_control`** maps DID strings to their `ControlInfo` (transaction key, storage signer, verification method fragment)
- **`issuer_did`** optionally holds the issuer's DID for the service

### 5.4 Credential Issuer (`credential/mod.rs`)

The Credential Issuer handles the creation, signing, and verification of W3C Verifiable Credentials.

**Initialization** loads an existing issuer identity from the storage path (`~/.iota-identity-service/issuer_identity.json`) if one exists. The persisted identity includes the issuer DID, the Ed25519 signing key in hex, the optional transaction key for blockchain operations, the verification method fragment, and the next revocation index. When loaded, the signing key is decoded from hex and the DID Manager and Revocation Manager are updated with the persisted state. If no identity exists, a fresh Ed25519 signing key is generated.

**Credential Issuance** (`issue_credential`) creates a full `DeviceCredential` following the W3C data model. The process:
1. A UUID-based credential ID is generated (e.g., `urn:uuid:550e8400-e29b-41d4-a716-446655440000`)
2. The credential subject is populated with the device's DID, type, capabilities, and optional metadata
3. A `CredentialStatus` is created by the on-chain revocation manager, which allocates the next available bitmap index and returns a reference to the RevocationBitmap2022 service
4. The credential body is assembled with W3C contexts (`https://www.w3.org/2018/credentials/v1` and `https://w3id.org/security/suites/ed25519-2020/v1`), types (`VerifiableCredential` and `IoTDeviceCredential`), the issuer DID, issuance date, expiration date (current time + configured validity), subject, and credential status
5. A proof is created by JSON-serializing the credential without proof, signing the bytes with the issuer's Ed25519 key, and Base64-encoding the signature
6. The proof is attached to the credential with metadata: type `Ed25519Signature2020`, creation timestamp, verification method reference (`<issuer-did>#issuer-key-1`), and purpose `assertionMethod`

**JWT Issuance** (`issue_credential_jwt`) wraps the credential in a JWT envelope. It creates a JWT header with `alg: EdDSA`, constructs the payload with standard JWT claims (`iss`, `sub`, `iat`, `exp`) alongside the `vc` claim containing the full credential, Base64url-encodes both parts, signs the `header.payload` string with the issuer's key, and returns the three-part JWT string.

**Credential Verification** (`verify_credential`) performs a multi-step validation:
1. **Expiration check** — Returns `CredentialExpired` if the current time exceeds the expiration date
2. **Revocation check** — If the credential has a `credentialStatus` of type `RevocationBitmap2022`, parses the revocation index and checks the on-chain revocation manager's local bitmap
3. **Proof validation** — Extracts the proof, determines the issuer's public key (using its own key for self-issued credentials), re-serializes the credential without proof, decodes the Base64 signature, and performs Ed25519 strict verification

**Persistence** (`save_issuer_identity_with_tx_key`) serializes the issuer identity to JSON and writes it to the configured storage path. The persisted data includes the DID, signing key hex, transaction key hex, verification method fragment, next revocation index, and creation timestamp. The `save_current_state()` method is called after each credential issuance to persist the updated revocation counter, ensuring no index collisions after a restart.

### 5.5 Cache Manager (`cache/mod.rs`)

The Cache Manager wraps two Moka asynchronous caches: one for DID Documents and one for credentials. Moka is a concurrent, lock-free caching library that supports TTL-based expiration and LRU eviction.

**DID Document Cache** stores `SimplifiedDIDDocument` objects keyed by DID string. Entries expire after 24 hours (configurable via `CacheConfig::did_ttl_secs`) and the maximum capacity is 100,000 entries. This cache dramatically reduces blockchain query latency for repeated DID resolutions — from ~75ms (cold) to ~0.13ms (cached).

**Credential Cache** stores credential validity status keyed by credential ID. Entries expire after 12 hours with a maximum capacity of 500,000 entries.

The manager tracks cache statistics including the number of entries in each cache and exposes methods for individual entry invalidation (used after key rotation, deactivation, or revocation) and bulk cache clearing (used by the admin endpoint).

### 5.6 Revocation Management (`revocation/mod.rs` and `revocation/bitmap.rs`)

The system implements two complementary revocation strategies:

**In-Memory Revocation Manager** (`RevocationManager`) maintains a `HashMap<String, RevocationEntry>` protected by a `RwLock`. Each entry records the credential ID, revocation timestamp, reason, and who initiated the revocation. This provides sub-microsecond revocation checks but entries are lost on restart. It supports revoking, checking status, un-revoking (for administrative purposes), and listing all revoked credentials. An atomic counter tracks total historical revocations.

**On-Chain Revocation Manager** (`OnChainRevocationManager`) implements the full RevocationBitmap2022 specification using a Roaring Bitmap from the `roaring` crate. The core data structures are:
- A `RoaringBitmap` that stores which indices are revoked
- An atomic `next_index` counter that allocates sequential indices to new credentials
- A `HashMap<String, u32>` mapping credential IDs to their bitmap indices
- A `HashMap<u32, RevocationInfo>` storing revocation metadata (reason, timestamp, who revoked)
- A `dirty` flag indicating whether the bitmap has been modified since its last on-chain publication

**Index Allocation** (`allocate_index`) atomically increments the counter and records the credential-to-index mapping. This is called during credential issuance.

**Revocation** (`revoke`) sets the bit at the given index in the bitmap, records the revocation info, and marks the bitmap as dirty. Attempting to revoke an already-revoked credential returns an error.

**Encoding** (`encode_service_endpoint`) serializes the Roaring Bitmap into bytes, compresses them with zlib, Base64-encodes the result, and wraps it in a data URL. This encoded string is what gets stored in the issuer's DID Document on the blockchain.

**Decoding** (`decode_service_endpoint`) performs the reverse: strips the data URL prefix, Base64-decodes, zlib-decompresses, and deserializes back into a `RoaringBitmap`. This static method is used by verifiers who need to check a bitmap they retrieved from the blockchain.

**Static Verification** (`check_revocation_status`) combines decoding with a bit check at a specific index. This is the method used by the Device Client's verifier during TLS authentication.

---

## 6. The Device Client (`device-client`)

The Device Client is the IoT device's representative in the system. It is a CLI application that manages the device's identity locally and communicates with the Identity Service and other devices.

### 6.1 CLI Interface (`main.rs`)

The CLI is built with `clap` and supports the following global options:
- `--identity-service <URL>` — the Identity Service URL (default: `http://localhost:8080`)
- `--network <name>` — the IOTA network to use (default: `testnet`)
- `--data-dir <path>` — the local storage directory (default: `./device-data`)

**`register`** registers the device with the Identity Service, creating a new DID and receiving a Verifiable Credential. It accepts `--device-type` (sensor, gateway, actuator, controller, edge, or generic) and `--capabilities` (comma-separated list). If the device is already registered, it prints the existing DID and suggests using `reregister`.

**`reregister`** clears all existing identity data and performs a fresh registration, effectively creating a new device identity. This is useful when a device's credential has expired or been revoked.

**`show`** displays the current device identity information including the DID, public key, device type, capabilities, and credential status. It warns if the credential has expired or will expire within 24 hours.

**`sign`** signs an arbitrary message with the device's Ed25519 private key and outputs the signature along with the public key and DID.

**`connect`** establishes a TLS connection to another device and performs mutual DID-based authentication. It takes the target address (host:port) and prints the peer's DID, public key, and detailed authentication metrics.

**`server`** starts a TLS server that listens for incoming connections from other devices. It accepts connections, performs DID-based authentication, and prints each authenticated client's DID.

**`resolve`** resolves a DID from the blockchain and prints the DID Document in pretty-printed JSON along with the resolution time and cache status.

**`clear`** deletes all stored device data including the private key, with confirmation prompt.

**`rotate-key`** generates a new Ed25519 key pair, submits the new public key to the Identity Service for on-chain key rotation, and updates the local private key file. The implementation uses a crash-safe approach: the new key is first written to a temporary file (`private_key.hex.new`), the on-chain rotation is performed, and only after success is the temporary file renamed to replace the old key.

### 6.2 Identity Manager (`identity/mod.rs`)

The Identity Manager is responsible for loading and interacting with the device's local identity state. It initializes from the configured storage directory, loading the identity JSON, credential JWT, and private key if they exist.

Key capabilities include:
- Checking whether the device is initialized (has a DID, credential, and private key)
- Signing challenges with the Ed25519 signing key (used during TLS authentication)
- Verifying signatures
- Checking credential expiration and warning about imminent expiry
- Parsing JWT expiration dates (supporting both standard Unix timestamp `exp` claims and W3C ISO 8601 `expirationDate` fields)
- Returning formatted identity information for display

### 6.3 Device Registration (`registration/mod.rs`)

The Device Registrar handles the full registration flow:

1. **Key Generation** — If no existing private key is found in storage, a new Ed25519 key pair is generated using the operating system's cryptographic random number generator (`OsRng`). If a key exists (from a previous registration), it is loaded and reused.

2. **API Call** — The device's public key (64 hex characters), device type, and capabilities are sent to the Identity Service's `/api/v1/device/register` endpoint via an HTTP POST request.

3. **Response Processing** — The Identity Service responds with the newly created DID, blockchain object ID, a signed JWT credential, and the credential's expiration date.

4. **Local Storage** — The registration data is persisted locally in the following order (most critical first): the private key is written to `private_key.hex`, the device identity metadata is serialized to `identity.json`, and the credential JWT is saved to `credential.jwt`.

The `re_register()` method clears all stored data, discards the current signing key, and performs a fresh registration from scratch.

### 6.4 DID Resolver (`resolver/mod.rs`)

The device-side DID Resolver implements a three-tier resolution strategy:

1. **Local Cache** — A Moka cache stores previously resolved `SimplifiedDIDDocument` objects with configurable TTL and capacity. Cache hits avoid any network access.

2. **Blockchain Resolution** — On a cache miss, the resolver attempts direct resolution from the IOTA Rebased blockchain using a read-only `IdentityClientReadOnly`. This does not require gas but takes ~75ms on Testnet.

3. **Identity Service Fallback** — If blockchain resolution fails (network issues, timeout), the resolver falls back to querying the Identity Service's `/api/v1/did/resolve` endpoint, which may have the document cached.

The resolver converts raw `IotaDocument` objects from the IOTA SDK into `SimplifiedDIDDocument` structures, extracting verification methods (with JWK-to-multibase conversion for public keys) and service endpoints.

### 6.5 Secure Storage (`storage/mod.rs`)

The Secure Storage module manages persistent local files:

- **`private_key.hex`** — The device's Ed25519 private key stored as 64 hex characters. On Unix systems, the file permissions are set to `0o600` (owner read/write only) for security.
- **`identity.json`** — The device identity metadata serialized as JSON.
- **`credential.jwt`** — The Verifiable Credential in JWT compact format.

The storage module provides atomic load and store operations, directory creation, existence checks, and a clear method that removes all files. It maintains an in-memory cache of the loaded identity for efficient access.

### 6.6 TLS with DID Authentication (`tls/mod.rs`)

The TLS module implements mutual authentication between IoT devices using TLS 1.3 for transport encryption and DID-based credentials for identity verification. This design separates the transport security concern (TLS) from the identity assurance concern (DID).

**TLS Transport Layer** — Both the TLS client and server use `rustls` for the TLS 1.3 implementation. The server generates a self-signed certificate using `rcgen` (since the certificate is not used for identity verification). The client uses a custom `AcceptAnyCertVerifier` that accepts any server certificate — this is intentional, because identity is verified at the DID layer, not the certificate layer. The TLS handshake establishes an encrypted, integrity-protected channel, and all subsequent DID authentication messages are transmitted over this channel.

**DID Authentication Protocol** — After the TLS handshake completes, a four-message DID authentication protocol runs over the encrypted channel:

1. **Client Hello** — The client sends a `DIDAuthMessage` of type Hello containing its DID, its credential JWT, its public key in hex, and a 32-byte random challenge for the server.

2. **Server Processing and Hello** — The server receives the client's hello, verifies the client's credential (JWT signature verification against the issuer's on-chain public key + revocation bitmap check), verifies that the client's claimed public key is present in their on-chain DID Document (public key binding check to prevent impersonation), signs the client's challenge with its own private key, generates its own challenge for the client, and sends a Hello message back containing its DID, credential JWT, public key, the challenge response, and its own challenge.

3. **Client Processing and Response** — The client verifies the server's credential and public key binding, validates the server's response to the client's challenge (proving the server possesses the private key corresponding to their DID), signs the server's challenge, and sends a Response message with the challenge response.

4. **Server Verification and Result** — The server verifies the client's challenge response and sends a Success or Failure message.

After successful authentication, both parties have:
- Verified that the other party possesses a valid, unexpired, unrevoked Verifiable Credential issued by a trusted issuer
- Verified that the other party possesses the private key corresponding to their on-chain DID Document (via challenge-response)
- Established an encrypted TLS 1.3 channel for further communication
- Collected detailed authentication metrics (TLS handshake time, credential verification time, challenge-response time, revocation check time, total time)

**Message Framing** — Messages are transmitted using a length-prefixed protocol: a 4-byte big-endian length header followed by the JSON-serialized message body. Messages larger than 1 MB are rejected.

### 6.7 Credential Verifier (`tls/verifier.rs`)

The Credential Verifier performs local verification of JWT credentials without requiring the Identity Service to be online (except for DID resolution, which can be served from cache).

**JWT Parsing** (`parse_credential`) splits the JWT into header, payload, and signature parts, Base64url-decodes the payload, and extracts all relevant fields: credential ID, subject DID, issuer DID, device type, capabilities, issuance and expiration dates, and the revocation index.

**Full Verification** (`verify_credential`) performs a five-step validation:
1. **Structure** — Validates the JWT has three parts
2. **Subject Matching** — Ensures the credential's subject DID matches the expected DID (the one claimed by the authenticating peer)
3. **Expiration** — Checks that the credential has not expired
4. **Signature** — Decodes the JWT header to confirm `alg: EdDSA`, resolves the issuer's DID Document from the blockchain (or cache), extracts the issuer's Ed25519 public key from the multibase-encoded verification method, reconstructs the signed message (`header.payload`), decodes the signature, and performs Ed25519 verification. If a `kid` (Key ID) is present in the JWT header, the matching verification method is preferred, enabling correct signature verification even after key rotation
5. **Revocation** — If revocation checking is enabled and the credential has a revocation index, resolves the issuer's DID Document, finds the RevocationBitmap2022 service, decodes the data URL (Base64 → zlib decompress → Roaring Bitmap), and checks whether the bit at the credential's index is set

**Public Key Binding Verification** (`verify_public_key_binding`) is a critical security function. During TLS authentication, a peer claims a DID and presents a public key for challenge-response. This function verifies that the claimed public key actually appears as a verification method in the peer's on-chain DID Document. Without this check, an attacker could present a valid credential belonging to another device alongside a different key pair.

**Multibase Key Decoding** (`decode_multibase_key`) handles the base58btc multibase format (prefix `z`) used by IOTA Identity. It decodes the base58 data and handles both the raw 32-byte key format and the 34-byte format with a multicodec prefix (`0xed01` for Ed25519).

---

## 7. The Benchmark Suite (`benchmarks`)

The benchmark suite measures the performance of all major system operations using HDR Histogram for statistically accurate latency recording.

### 7.1 Benchmark Types

**DID Creation** measures the time to register a new device (which includes publishing a DID Document on the blockchain). For each iteration, a fresh Ed25519 key pair is generated and submitted to the `/api/v1/device/register` endpoint. This is the slowest operation (~1 second on Testnet) because it involves a blockchain transaction.

**DID Resolution (Cold)** measures blockchain lookup time with an empty cache. Before each iteration, the cache is cleared via the admin endpoint. Expected time is ~75ms on Testnet.

**DID Resolution (Cached)** measures the time to retrieve a previously resolved DID Document from the Moka cache. The DID is resolved once to prime the cache, then subsequent accesses measure pure cache hit performance. Expected time is <1ms.

**Credential Issuance** measures the full registration flow (DID creation + credential issuance). The credential issuance itself is <5ms but is bundled with the DID creation in the benchmark.

**Credential Verification** measures the time to verify a previously issued credential via the `/api/v1/credential/verify` endpoint. Expected time is <1ms with a warm cache.

**Revocation Check** measures the time to check the on-chain revocation status of a credential index via the `/api/v1/credential/status-onchain` endpoint. This is a local bitmap lookup. Expected time is <1ms.

**Full Device Registration** measures the complete end-to-end registration flow as a single operation.

### 7.2 Methodology

Each benchmark follows the same pattern:
1. **Warm-up** — 2 iterations (configurable) are run and discarded to eliminate JIT compilation effects and prime network connections
2. **Measurement** — N iterations (default 10) are timed using `Instant::now()` with microsecond precision
3. **Recording** — Each latency is recorded in an HDR Histogram configured with bounds from 1µs to 60s at 3 significant digits
4. **Reporting** — The histogram computes min, max, mean, median, P95, P99, and standard deviation

Slow benchmarks (DID creation, device registration) are automatically reduced to 3 iterations when running the full suite.

### 7.3 Output

Results are displayed in a formatted console table and optionally exported to CSV with columns for benchmark name, iteration count, all statistical metrics, and a timestamp. JSON export is also available from historical benchmark runs stored in the project root.

---

## 8. Operational Flows

### 8.1 System Initialization

```
1. Start Identity Service
   ├── Load configuration from environment
   ├── Connect to IOTA Rebased network
   ├── Request faucet funds (Testnet/Devnet)
   ├── Initialize DID Manager with IdentityClient
   ├── Try to load existing issuer identity from disk
   │   ├── If found: restore signing key, DID, control info
   │   └── If not: generate new Ed25519 signing key
   ├── Initialize Cache Manager, Revocation Managers
   └── Start HTTP server on port 8080

2. Initialize Issuer (first time only)
   POST /api/v1/issuer/initialize
   ├── Create issuer DID Document on-chain with public key
   ├── Generate transaction key pair for future updates
   ├── Add RevocationBitmap2022 service (empty bitmap)
   ├── Persist issuer identity to ~/.iota-identity-service/
   └── Return issuer DID
```

### 8.2 Device Registration

```
Device Client                    Identity Service             IOTA Blockchain
     │                                  │                           │
     │  generate Ed25519 keypair        │                           │
     │  POST /device/register ────────► │                           │
     │  {public_key, type, caps}        │                           │
     │                                  │  create DID Document      │
     │                                  │  with device's public key │
     │                                  │  publish to chain ──────► │
     │                                  │                    ◄───── │ DID + object_id
     │                                  │                           │
     │                                  │  allocate revocation index│
     │                                  │  issue W3C VC (JWT)       │
     │                                  │  sign with Ed25519 key    │
     │                                  │  persist revocation index │
     │                                  │                           │
     │ ◄──────────────────────────────  │                           │
     │ {did, object_id, jwt, expires}   │                           │
     │                                  │                           │
     │  store private_key.hex           │                           │
     │  store identity.json             │                           │
     │  store credential.jwt            │                           │
```

### 8.3 Credential Verification

```
Verifier                      Identity Service              IOTA Blockchain
     │                               │                              │
     │  POST /credential/verify      │                              │
     │  {credential_jwt} ──────────► │                              │
     │                               │  decode JWT                  │
     │                               │  check in-memory revocations │
     │                               │  check expiration            │
     │                               │  check RevocationBitmap2022  │
     │                               │  verify Ed25519 signature    │
     │ ◄──────────────────────────── │                              │
     │ {valid, subject, issuer, exp} │                              │
```

### 8.4 On-Chain Revocation

```
Admin                         Identity Service              IOTA Blockchain
     │                               │                            │
     │  POST /credential/revoke-onchain                           │
     │  {credential_id, index} ────► │                            │
     │                               │  set bit in RoaringBitmap  │
     │                               │  compress with zlib        │
     │                               │  encode as data URL        │
     │                               │  update DID Document ────► │
     │                               │  service endpoint          │
     │                               │                     ◄───── │ published
     │                               │  invalidate caches         │
     │ ◄──────────────────────────── │                            │
     │ {success, on_chain: true}     │                            │
```

### 8.5 TLS Mutual Authentication

```
Client Device              Server Device               Identity Service / Blockchain
     │                         │                               │
     │── TCP Connect ────────► │                               │
     │── TLS 1.3 Handshake ──► │                               │
     │◄─ TLS Established ───── │                               │
     │                         │                               │
     │── Hello ───────────────►│                               │
     │   (DID, JWT, pubkey,    │                               │
     │    challenge)           │                               │
     │                         │── resolve issuer DID ────────►│
     │                         │◄── DID Document ──────────────│
     │                         │   verify JWT signature        |
     │                         │── resolve client DID ────────►│
     │                         │◄── DID Document ──────────────│
     │                         │   verify pubkey binding       │
     │                         │   check RevocationBitmap2022  │
     │                         │   sign client's challenge     │
     │                         │                               │
     │◄─ Hello ────────────────│                               │
     │   (DID, JWT, pubkey,    │                               │
     │    challenge,           │                               │
     │    challenge_response)  │                               │
     │                         │                               │
     │   verify server JWT     │                               │
     │── resolve issuer DID ──►│              ────────────────►│
     │◄─ DID Document ──────── │              ◄────────────────│ 
     │   verify pubkey binding │                               │
     │   verify challenge resp │                               │
     │   sign server's challenge│                              │
     │                         │                               │
     │── Response ────────────►│                               │
     │   (challenge_response)  │                               │
     │                         │   verify challenge response   │
     │◄─ Success ──────────────│                               │
     │                         │                               │
     │═══ Authenticated Channel═│                              │
```

---

## 9. Security Model

### 9.1 Trust Assumptions

The system makes the following trust assumptions:

1. **IOTA Rebased blockchain** is assumed to provide integrity and availability for DID Documents. The ledger's consensus mechanism ensures that DID Documents cannot be tampered with after publication.

2. **The Identity Service** is the sole trusted issuer. It holds the signing key used to create Verifiable Credentials. Compromise of the issuer's signing key would allow an attacker to forge credentials.

3. **Ed25519 cryptography** is assumed to be secure. All key generation uses the operating system's cryptographic random number generator.

4. **TLS 1.3** provides transport confidentiality and integrity between communicating devices.

### 9.2 Threat Mitigations

**Credential Forgery** — Credentials are signed with the issuer's Ed25519 key. Verifiers resolve the issuer's DID from the blockchain and use the on-chain public key to verify signatures, making forgery infeasible without the issuer's private key.

**Impersonation** — During TLS authentication, the public key binding check (`verify_public_key_binding`) ensures that the peer's claimed public key matches a verification method in their on-chain DID Document. An attacker cannot present someone else's valid credential with a different key pair.

**Replay Attacks** — The challenge-response protocol uses 32-byte random challenges generated for each authentication session. A replayed challenge-response pair will not match the fresh challenge.

**Revoked Credentials** — The RevocationBitmap2022 allows immediate revocation verification. Once a credential is revoked and the bitmap is published on-chain, any verifier that resolves the issuer's DID Document will see the revocation, even without contacting the issuer.

**Man-in-the-Middle** — The TLS 1.3 handshake prevents MitM attacks on the transport layer. The DID authentication layer on top prevents identity-level MitM by verifying credentials and challenge-responses.

**Key Compromise** — The key rotation feature allows a device to replace its compromised key with a new one. The new key is published as a new verification method in the DID Document on-chain.

### 9.3 Design Decisions

**Self-signed TLS certificates** — The system intentionally bypasses X.509 certificate validation during TLS handshake because identity assurance comes from the DID layer, not certificates. The TLS layer provides only transport encryption.

**In-memory key storage** — The IOTA Identity Stronghold integration is not yet available for Rebased, so the system uses `JwkMemStore`. For production deployments, a hardware security module or the Stronghold library should be integrated when available.

**Private key storage** — Device private keys are stored as hex files on disk with restricted permissions (0o600 on Unix). For production, these should be stored in a secure enclave or TPM.

---

## 10. Performance Analysis

### 10.1 Measured Latencies (IOTA Testnet)

| Operation                  | Mean      | P95       | P99       | Notes                                |
|----------------------------|-----------|-----------|-----------|--------------------------------------|
| DID Resolution (Cached)   | 0.13 ms   | 0.24 ms   | 0.24 ms   | Moka cache lookup                    |
| Revocation Check           | 0.13 ms   | 0.18 ms   | 0.18 ms   | RoaringBitmap bit test               |
| Credential Verification    | 0.24 ms   | 0.38 ms   | 0.38 ms   | Ed25519 signature + revocation check |
| DID Resolution (Cold)      | 74.85 ms  | 149.12 ms | 149.12 ms | Blockchain RPC round-trip            |
| TLS + DID Authentication   | ~127 ms   | —         | —         | Full mutual authentication           |
| Device Registration        | 934 ms    | 943 ms    | 943 ms    | Blockchain transaction + credential  |
| DID Creation               | 1010 ms   | 1214 ms   | 1214 ms   | Blockchain transaction only          |

### 10.2 Comparison with Traditional PKI

| Aspect                      | This System                     | Traditional PKI                    |
|-----------------------------|----------------------------------|-------------------------------------|
| Revocation Check Latency    | 0.13 ms (local bitmap)          | 19–291 ms (OCSP)                   |
| Worst-Case Revocation       | 0.13 ms                         | 5 seconds to 8 minutes (long tail) |
| Revocation Failure Rate     | 0% (on-chain, self-contained)   | Up to 6% (CA OCSP responders)      |
| Offline Verification        | Yes (cached DID Document)       | No (requires OCSP online check)    |
| Single Point of Failure     | No (blockchain consensus)       | Yes (Certificate Authority)        |
| Privacy                     | Verifier does not contact CA    | CA observes all validation requests|
| Mobile Revocation Support   | Full support                    | Browsers never check (Liu et al.)  |
| Scalability                 | Decentralized                   | Centralized bottleneck             |

### 10.3 Performance Characteristics

The system exhibits a bimodal performance profile. Operations that touch the blockchain (DID creation, registration, key rotation, deactivation, revocation publication) take on the order of 1 second due to the latency of submitting and confirming a transaction on the IOTA Rebased ledger. Once the initial setup is complete, however, all verification operations run in sub-millisecond time thanks to local caching and in-memory bitmap lookups. This makes the system well-suited to the IoT use case where device registration is a one-time event but credential and revocation verification happen continuously.

---

## 11. Persistence and Data Management

### 11.1 Identity Service Persistence

The issuer identity is stored at `~/.iota-identity-service/issuer_identity.json`:

```json
{
  "did": "did:iota:testnet:0x...",
  "signing_key_hex": "abcdef1234...",
  "tx_key_hex": "fedcba4321...",
  "verification_method_fragment": "#signing-key",
  "next_revocation_index": 42,
  "created_at": "2026-02-25T12:00:00Z"
}
```

- **`did`** — The issuer's on-chain DID
- **`signing_key_hex`** — The Ed25519 private key used to sign credentials (64 hex chars)
- **`tx_key_hex`** — The Ed25519 private key used to sign blockchain transactions (DID updates, revocation bitmap updates). This is separate from the signing key to support different key management policies
- **`verification_method_fragment`** — The fragment identifier of the signing key in the DID Document (e.g., `#signing-key`)
- **`next_revocation_index`** — The next available index in the revocation bitmap, persisted to prevent index collisions after restart
- **`created_at`** — Timestamp of the original issuer initialization

On startup, the service loads this file, restores the signing key, reconstructs the DID control info (allowing it to sign future transactions for the issuer's DID), and resumes the revocation counter from the persisted value.

### 11.2 Device Client Persistence

Each device stores its identity in the configured data directory (default `./device-data/`):

**`private_key.hex`** — The device's Ed25519 private key as 64 hexadecimal characters. File permissions are restricted to owner-only on Unix systems.

**`identity.json`** — Device metadata including the DID, blockchain object ID, public key, device type, capabilities, and timestamps.

**`credential.jwt`** — The W3C Verifiable Credential in JWT compact format, as received from the Identity Service during registration.

---

## 12. Configuration Reference

### 12.1 Environment Variables

| Variable              | Default    | Description                                              |
|----------------------|------------|----------------------------------------------------------|
| `IOTA_NETWORK`       | `testnet`  | IOTA Rebased network: testnet, devnet, mainnet, local    |
| `IOTA_IDENTITY_PKG_ID` | (required) | The Move package ID for IOTA Identity on the chosen network |
| `RUST_LOG`           | `info`     | Log level: trace, debug, info, warn, error               |
| `STRONGHOLD_PASSWORD` | —         | Reserved for future Stronghold integration               |

### 12.2 Network Configuration

| Network   | RPC Endpoint                       | Faucet                                  | Package ID                                                            |
|-----------|------------------------------------|-----------------------------------------|-----------------------------------------------------------------------|
| Testnet   | `https://api.testnet.iota.cafe`    | `https://faucet.testnet.iota.cafe/gas`  | `0x222741bbdff74b42df48a7b4733185e9b24becb8ccfbafe8eac864ab4e4cc555` |
| Devnet    | `https://api.devnet.iota.cafe`     | `https://faucet.devnet.iota.cafe/gas`   | Same as Testnet (may change)                                          |
| Mainnet   | `https://api.mainnet.iota.cafe`    | N/A (pre-funded account required)       | Must be provided via environment variable                             |
| Local     | `http://127.0.0.1:9000`           | `http://127.0.0.1:9123/gas`            | Must be provided via environment variable                             |

### 12.3 Gas Budgets

| Operation            | Gas Budget   |
|---------------------|-------------|
| DID Publication      | 50,000,000  |
| DID Update           | 30,000,000  |
| DID Deactivation     | 20,000,000  |
| Revocation Update    | 25,000,000  |

### 12.4 Default Parameters

| Parameter                        | Default Value  |
|----------------------------------|---------------|
| API Port                         | 8080          |
| Max Request Body                 | 1 MB          |
| DID Cache TTL                    | 24 hours      |
| Credential Cache TTL             | 12 hours      |
| Max Cached DID Documents         | 100,000       |
| Max Cached Credentials           | 500,000       |
| Credential Validity              | 365 days      |
| TLS Certificate Validity         | 90 days       |
| TLS Handshake Timeout            | 30 seconds    |
| TLS Authentication Timeout       | 60 seconds    |

---

## 13. Technology Stack

### 13.1 Language and Runtime

The entire system is written in **Rust (edition 2021)**, targeting Rust 1.75 or later. Rust was chosen for its memory safety guarantees (no null pointer dereferences, no data races, no buffer overflows), zero-cost abstractions, and suitability for both server and embedded environments. The release build profile uses opt-level 3 and thin LTO for maximum performance.

### 13.2 Core Dependencies

| Category           | Library                | Version    | Purpose                                                 |
|-------------------|------------------------|------------|--------------------------------------------------------|
| **Blockchain**     | `identity_iota`       | Git (main) | IOTA Rebased Identity SDK — DID and VC operations       |
|                    | `identity_storage`    | Git (main) | Storage abstractions for key management                |
| **Web Framework** | `axum`                | 0.8.8      | HTTP server with extractors and routing                 |
|                    | `tower` / `tower-http` | —         | Middleware (CORS, timeout)                              |
|                    | `tokio`               | 1.35       | Async runtime with multi-threaded scheduler             |
| **Cryptography**   | `ed25519-dalek`       | 2.1        | Ed25519 key generation, signing, verification           |
|                    | `sha2`                | 0.10       | SHA-256 hashing                                         |
|                    | `rand`                | 0.8        | Cryptographic random number generation                  |
| **TLS**           | `rustls`              | 0.23       | Pure-Rust TLS 1.3 implementation                        |
|                    | `tokio-rustls`        | 0.26       | Async TLS integration with tokio                        |
|                    | `rcgen`               | 0.13       | Self-signed certificate generation                      |
|                    | `x509-parser`         | 0.16       | X.509 certificate parsing                               |
| **Caching**        | `moka`                | 0.12       | Concurrent async cache with TTL and LRU eviction        |
| **Revocation**     | `roaring`             | 0.10       | Roaring Bitmap for RevocationBitmap2022                 |
|                    | `flate2`              | 1.0        | Zlib compression for bitmap serialization               |
| **Serialization** | `serde` / `serde_json` | 1.0       | JSON serialization framework                            |
|                    | `base64`              | 0.22       | Base64 encoding for JWTs and data URLs                  |
|                    | `hex`                 | 0.4        | Hex encoding for keys                                   |
|                    | `bs58`                | —          | Base58 encoding for multibase keys                      |
| **CLI**            | `clap`                | 4.4        | Command-line argument parsing with derive macros         |
| **HTTP Client**    | `reqwest`             | 0.12       | Async HTTP client for API calls and fallback resolution  |
| **Logging**        | `tracing`             | 0.1        | Structured, async-aware logging                          |
|                    | `tracing-subscriber`  | 0.3        | Log formatting with environment filter                   |
| **Error Handling** | `thiserror`           | 1.0        | Derive macro for error types                             |
|                    | `anyhow`              | 1.0        | Flexible error handling for application code             |
| **Concurrency**    | `parking_lot`         | 0.12       | Fast RwLock implementation                               |
| **Time**           | `chrono`              | 0.4        | Date/time handling with timezone support                  |
| **IDs**            | `uuid`                | 1.6        | UUID generation for credential IDs                        |
| **Benchmarking**   | `hdrhistogram`        | 0.5        | HDR Histogram for latency percentile calculations         |

### 13.3 Utility Scripts

The `tools/` directory contains Python and Bash scripts for operational support:

- **`accumulate_tokens.py`** — Automates requesting testnet tokens from the IOTA faucet, running repeated requests until a target balance is reached
- **`derive_address.py`** — Derives the issuer's wallet address from the stored transaction key for checking balance
- **`run_benchmarks.sh`** — Orchestrates the full benchmark workflow: builds the project, starts the Identity Service, waits for readiness, runs the benchmark suite, and collects results

---

*This document describes the complete functionality of the IOTA Identity IoT system as implemented in the source code. Every module, endpoint, data structure, protocol, and configuration option is covered.*
