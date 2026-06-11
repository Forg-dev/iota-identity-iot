# IOTA Identity IoT System - Analisi Completa della Codebase

## Indice

1. [Panoramica del Progetto](#panoramica-del-progetto)
2. [Crate shared/](#crate-shared)
3. [Crate identity-service/](#crate-identity-service)
4. [Crate device-client/](#crate-device-client)
5. [Crate benchmarks/](#crate-benchmarks)
6. [Tools Python](#tools-python)
7. [Flussi End-to-End](#flussi-end-to-end)
8. [Gestione della Cache](#gestione-della-cache)
9. [Propagazione degli Errori](#propagazione-degli-errori)
10. [Interazione con IOTA Blockchain](#interazione-con-iota-blockchain)

---

## Panoramica del Progetto

Il progetto implementa un sistema di identità decentralizzata (DID) per dispositivi IoT basato su IOTA Rebased blockchain. L'architettura si compone di:

- **shared/**: Tipi comuni, configurazione, costanti e gestione errori
- **identity-service/**: Server REST per gestione DID, credenziali e revoca on-chain
- **device-client/**: Client CLI per dispositivi IoT con TLS e autenticazione DID
- **benchmarks/**: Suite di benchmark per misurare le performance del sistema

### Dipendenze Principali

```toml
identity_iota = { git = "https://github.com/iotaledger/identity.rs" }  # SDK IOTA Identity
tokio = "1.43"           # Runtime async
axum = "0.8"             # Web framework
rustls = "0.23"          # TLS
moka = "0.12"            # Cache async
ed25519-dalek = "2.1"    # Crittografia Ed25519
roaring = "0.10"         # Bitmap compressi per revoca
```

---

## Crate shared/

Il crate `shared` fornisce i tipi e le configurazioni condivise tra tutti i componenti del sistema.

### File: `shared/src/lib.rs`

**Scopo**: Entry point del crate, espone i moduli pubblici.

```rust
pub mod config;
pub mod constants;
pub mod error;
pub mod types;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
```

---

### File: `shared/src/config.rs`

**Scopo**: Definisce tutte le strutture di configurazione per il sistema.

#### Enum `IotaNetwork`

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IotaNetwork {
    Testnet,
    Devnet,
    Mainnet,
    Local,
}
```

**Campi e Significato**:
- `Testnet`: Rete di test IOTA Rebased (endpoint: `https://api.testnet.iota.cafe`)
- `Devnet`: Rete di sviluppo
- `Mainnet`: Rete principale (non ancora disponibile)
- `Local`: Nodo locale per sviluppo

**Metodi**:
- `endpoint(&self) -> &str`: Restituisce l'URL dell'endpoint RPC per la rete
- `from_str(s: &str) -> Self`: Parser case-insensitive per il nome della rete

#### Struct `IdentityServiceConfig`

```rust
pub struct IdentityServiceConfig {
    pub network: IotaNetwork,
    pub custom_endpoint: Option<String>,
    pub api: ApiConfig,
    pub cache: CacheConfig,
    pub storage: StorageConfig,
    pub credential: CredentialConfig,
}
```

**Campi**:
- `network`: La rete IOTA da utilizzare
- `custom_endpoint`: Override opzionale dell'endpoint (utile per nodi privati)
- `api`: Configurazione del server HTTP (host, porta)
- `cache`: Configurazione della cache (TTL, capacità massima)
- `storage`: Percorsi per storage persistente
- `credential`: Configurazione credenziali (validità, issuer)

**Metodo `from_env()`**:
Carica la configurazione da variabili d'ambiente:
1. Legge `IOTA_NETWORK` (default: "testnet")
2. Legge `IOTA_ENDPOINT` per override
3. Legge `API_HOST` e `API_PORT`
4. Legge `CACHE_*` per TTL e capacità
5. Legge `STORAGE_*` per percorsi
6. Legge `CREDENTIAL_*` per durata validità

#### Struct `ApiConfig`

```rust
pub struct ApiConfig {
    pub host: String,
    pub port: u16,
}
```

**Metodo `listen_addr(&self) -> String`**: Combina host e porta in formato `host:port`.

#### Struct `CacheConfig`

```rust
pub struct CacheConfig {
    pub did_ttl_secs: u64,
    pub credential_ttl_secs: u64,
    pub max_did_documents: u64,
    pub max_credentials: u64,
}
```

**Campi**:
- `did_ttl_secs`: Time-to-live per DID Document in cache (default: 3600s)
- `credential_ttl_secs`: TTL per credenziali verificate (default: 1800s)
- `max_did_documents`: Numero massimo di DID in cache (default: 10000)
- `max_credentials`: Numero massimo di credenziali (default: 50000)

#### Struct `StorageConfig`

```rust
pub struct StorageConfig {
    pub stronghold_path: PathBuf,
    pub stronghold_password: Option<String>,
    pub data_path: PathBuf,
}
```

**Campi**:
- `stronghold_path`: Percorso per IOTA Stronghold (secure enclave)
- `stronghold_password`: Password per Stronghold (opzionale)
- `data_path`: Directory per dati persistenti

#### Struct `CredentialConfig`

```rust
pub struct CredentialConfig {
    pub validity_hours: u64,
    pub issuer_name: String,
}
```

**Campi**:
- `validity_hours`: Durata validità credenziali in ore (default: 8760 = 1 anno)
- `issuer_name`: Nome dell'issuer per le credenziali

#### Struct `DeviceClientConfig`

```rust
pub struct DeviceClientConfig {
    pub network: IotaNetwork,
    pub custom_endpoint: Option<String>,
    pub identity_service_url: String,
    pub storage: StorageConfig,
    pub cache: CacheConfig,
    pub tls: TlsConfig,
}
```

Configurazione specifica per il client dispositivo IoT.

#### Struct `TlsConfig`

```rust
pub struct TlsConfig {
    pub handshake_timeout_ms: u64,
    pub auth_timeout_ms: u64,
    pub challenge_size: usize,
}
```

**Campi**:
- `handshake_timeout_ms`: Timeout per handshake TLS (default: 10000ms)
- `auth_timeout_ms`: Timeout per autenticazione DID post-handshake (default: 30000ms)
- `challenge_size`: Dimensione challenge per protocollo challenge-response (default: 32 byte)

---

### File: `shared/src/constants.rs`

**Scopo**: Definisce tutte le costanti del sistema.

#### Costanti di Rete

```rust
pub const IOTA_TESTNET_ENDPOINT: &str = "https://api.testnet.iota.cafe";
pub const IOTA_DEVNET_ENDPOINT: &str = "https://api.devnet.iota.cafe";
pub const IOTA_MAINNET_ENDPOINT: &str = "https://api.iota.cafe";
pub const IOTA_LOCAL_ENDPOINT: &str = "http://localhost:9000";
```

#### Package ID IOTA

```rust
pub const IOTA_IDENTITY_PACKAGE_ID: &str =
    "0x7a67dd504eb1291958495c71a07d20985951648dd99fd6b6cfb880dc2b8ec029";
```

Identificativo del package Move per IOTA Identity su Rebased.

#### Gas Budget

```rust
pub const DEFAULT_GAS_BUDGET: u64 = 50_000_000;  // 50M IOTA (0.05 IOTA)
pub const DID_CREATION_GAS: u64 = 100_000_000;   // 100M per creazione DID
pub const KEY_ROTATION_GAS: u64 = 75_000_000;    // 75M per rotazione chiave
pub const REVOCATION_GAS: u64 = 50_000_000;      // 50M per revoca
```

#### Cache

```rust
pub const DEFAULT_DID_CACHE_TTL: u64 = 3600;        // 1 ora
pub const DEFAULT_CREDENTIAL_CACHE_TTL: u64 = 1800; // 30 minuti
pub const MAX_CACHE_ENTRIES: u64 = 10000;
```

#### Credenziali

```rust
pub const DEFAULT_CREDENTIAL_VALIDITY_HOURS: u64 = 8760; // 1 anno
pub const CREDENTIAL_CONTEXT: &str = "https://www.w3.org/2018/credentials/v1";
pub const IOT_CREDENTIAL_TYPE: &str = "IoTDeviceCredential";
```

#### TLS

```rust
pub const TLS_HANDSHAKE_TIMEOUT_MS: u64 = 10000;
pub const DID_AUTH_TIMEOUT_MS: u64 = 30000;
pub const CHALLENGE_SIZE: usize = 32;
```

#### Variabili d'Ambiente

```rust
pub const ENV_IOTA_NETWORK: &str = "IOTA_NETWORK";
pub const ENV_IOTA_ENDPOINT: &str = "IOTA_ENDPOINT";
pub const ENV_API_HOST: &str = "API_HOST";
pub const ENV_API_PORT: &str = "API_PORT";
// ... altre variabili
```

---

### File: `shared/src/error.rs`

**Scopo**: Sistema unificato di gestione errori per tutto il progetto.

#### Enum `IdentityError`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IdentityError {
    // Errori DID
    InvalidDID(String),
    DIDNotFound(String),
    DIDCreationFailed { reason: String },
    DIDResolutionError { did: String, reason: String },
    DIDDeactivationError { did: String, reason: String },

    // Errori Credenziali
    CredentialNotFound { credential_id: String },
    CredentialExpired { credential_id: String, expired_at: String },
    CredentialRevoked { credential_id: String },
    CredentialVerificationFailed { reason: String },
    InvalidCredentialFormat(String),
    CredentialIssuanceFailed { reason: String },

    // Errori Crittografici
    SignatureVerificationFailed { reason: String },
    InvalidSignature(String),
    KeyGenerationFailed(String),
    InvalidPublicKey(String),

    // Errori di Rete
    NetworkConnectionError { endpoint: String, reason: String },
    BlockchainError { operation: String, reason: String },
    TransactionFailed { tx_id: String, reason: String },

    // Errori TLS
    TlsHandshakeFailed { reason: String },
    TlsConfigurationError(String),
    CertificateError(String),

    // Errori di Storage
    StorageIOError(String),
    SerializationError(String),

    // Errori di Autenticazione
    AuthenticationFailed { reason: String },
    ChallengeResponseFailed { reason: String },

    // Altri
    ConfigurationError(String),
    InternalError(String),
    NotImplemented(String),
}
```

#### Type Alias

```rust
pub type IdentityResult<T> = Result<T, IdentityError>;
```

#### Implementazioni

**`impl std::fmt::Display for IdentityError`**:
Formatta ogni variante in un messaggio leggibile.

**`impl std::error::Error for IdentityError`**:
Implementazione standard per compatibilità con l'ecosistema Rust.

**`impl From<...> for IdentityError`**:
Conversioni automatiche da:
- `std::io::Error` → `StorageIOError`
- `serde_json::Error` → `SerializationError`
- `reqwest::Error` → `NetworkConnectionError`

#### Metodi di Utilità

```rust
impl IdentityError {
    pub fn category(&self) -> &'static str {
        match self {
            Self::InvalidDID(_) | Self::DIDNotFound(_) | ... => "DID",
            Self::CredentialNotFound { .. } | ... => "Credential",
            Self::SignatureVerificationFailed { .. } | ... => "Cryptography",
            Self::NetworkConnectionError { .. } | ... => "Network",
            Self::TlsHandshakeFailed { .. } | ... => "TLS",
            Self::StorageIOError(_) | ... => "Storage",
            Self::AuthenticationFailed { .. } | ... => "Authentication",
            _ => "Other",
        }
    }

    pub fn is_retryable(&self) -> bool {
        matches!(self,
            Self::NetworkConnectionError { .. } |
            Self::TransactionFailed { .. } |
            Self::TlsHandshakeFailed { .. }
        )
    }
}
```

- `category()`: Raggruppa gli errori per categoria (utile per logging/metriche)
- `is_retryable()`: Indica se l'operazione può essere ritentata

---

### File: `shared/src/types.rs`

**Scopo**: Definisce tutti i tipi di dati condivisi tra i componenti.

#### Struct `DeviceIdentity`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub did: String,
    pub object_id: String,
    pub public_key: String,
    pub device_type: DeviceType,
    pub capabilities: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub status: DeviceStatus,
}
```

**Campi**:
- `did`: Identificatore DID completo (es. `did:iota:testnet:0x...`)
- `object_id`: ID oggetto on-chain (IOTA Rebased usa oggetti, non UTXO)
- `public_key`: Chiave pubblica Ed25519 in formato hex
- `device_type`: Tipo di dispositivo
- `capabilities`: Lista di capacità (es. `["temperature", "humidity"]`)
- `created_at`: Timestamp di creazione
- `status`: Stato corrente del dispositivo

**Metodo Costruttore**:
```rust
impl DeviceIdentity {
    pub fn new(
        did: String,
        object_id: String,
        public_key: String,
        device_type: DeviceType,
        capabilities: Vec<String>,
    ) -> Self {
        Self {
            did,
            object_id,
            public_key,
            device_type,
            capabilities,
            created_at: chrono::Utc::now(),
            status: DeviceStatus::Active,
        }
    }
}
```

#### Enum `DeviceType`

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceType {
    Sensor,
    Gateway,
    Actuator,
    Controller,
    Edge,
    Generic,
}
```

Rappresenta i tipi di dispositivi IoT supportati.

#### Enum `DeviceStatus`

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceStatus {
    Active,
    Inactive,
    Revoked,
    Pending,
}
```

#### Struct `DeviceCredential`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "type")]
    pub credential_type: Vec<String>,
    pub issuer: String,
    #[serde(rename = "issuanceDate")]
    pub issuance_date: String,
    #[serde(rename = "expirationDate")]
    pub expiration_date: Option<String>,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: CredentialSubject,
    #[serde(rename = "credentialStatus")]
    pub credential_status: Option<CredentialStatus>,
    pub proof: Option<CredentialProof>,
}
```

Struttura conforme allo standard W3C Verifiable Credentials.

**Campi**:
- `context`: Contesti JSON-LD (sempre include `https://www.w3.org/2018/credentials/v1`)
- `id`: Identificatore univoco della credenziale
- `credential_type`: Tipi della credenziale (es. `["VerifiableCredential", "IoTDeviceCredential"]`)
- `issuer`: DID dell'issuer
- `issuance_date`: Data di emissione ISO 8601
- `expiration_date`: Data di scadenza (opzionale)
- `credential_subject`: Soggetto della credenziale
- `credential_status`: Informazioni per verifica revoca (RevocationBitmap2022)
- `proof`: Firma crittografica

#### Struct `CredentialSubject`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSubject {
    pub id: String,
    #[serde(rename = "deviceType")]
    pub device_type: DeviceType,
    pub capabilities: Vec<String>,
    #[serde(rename = "publicKey")]
    pub public_key: String,
}
```

#### Struct `CredentialStatus`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialStatus {
    pub id: String,
    #[serde(rename = "type")]
    pub status_type: String,
    #[serde(rename = "revocationBitmapIndex")]
    pub revocation_bitmap_index: Option<String>,
}
```

**Campi**:
- `id`: URI del servizio di revoca (es. `did:iota:...#revocation`)
- `status_type`: Sempre `"RevocationBitmap2022"`
- `revocation_bitmap_index`: Indice nel bitmap di revoca

#### Struct `CredentialProof`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub created: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}
```

Firma Ed25519 sulla credenziale.

#### Struct `SimplifiedDIDDocument`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimplifiedDIDDocument {
    pub id: String,
    #[serde(rename = "verificationMethod")]
    pub verification_methods: Vec<VerificationMethod>,
    pub authentication: Option<Vec<String>>,
    pub service: Option<Vec<Service>>,
    pub updated: Option<String>,
}
```

Versione semplificata del DID Document per uso interno.

#### Struct `VerificationMethod`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    pub controller: String,
    #[serde(rename = "type")]
    pub key_type: String,
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}
```

**Campi**:
- `id`: URI del metodo (es. `did:iota:...#key-1`)
- `controller`: DID che controlla la chiave
- `key_type`: Tipo di chiave (es. `JsonWebKey2020`)
- `public_key_multibase`: Chiave pubblica in formato multibase (prefisso `z` = base58btc)

#### Struct `Service`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}
```

Servizi associati al DID (es. revocation service).

---

#### Tipi di Richiesta/Risposta API

##### `DeviceRegistrationRequest`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRegistrationRequest {
    pub public_key: String,
    pub device_type: DeviceType,
    pub capabilities: Vec<String>,
}
```

##### `DeviceRegistrationResponse`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRegistrationResponse {
    pub did: String,
    pub object_id: String,
    pub credential_jwt: String,
    pub credential_expires_at: String,
}
```

##### `CredentialVerificationRequest`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialVerificationRequest {
    pub credential_jwt: String,
}
```

##### `CredentialVerificationResponse`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialVerificationResponse {
    pub valid: bool,
    pub subject_did: Option<String>,
    pub issuer_did: Option<String>,
    pub error: Option<String>,
    pub verified_at: String,
}
```

##### `OnChainRevocationRequest`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnChainRevocationRequest {
    pub credential_id: String,
    pub reason: Option<String>,
}
```

##### `OnChainRevocationResponse`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnChainRevocationResponse {
    pub success: bool,
    pub credential_id: String,
    pub revocation_index: Option<u32>,
    pub transaction_id: Option<String>,
    pub error: Option<String>,
}
```

##### `CredentialStatusResponse`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialStatusResponse {
    pub credential_id: String,
    pub revoked: bool,
    pub revocation_index: Option<u32>,
    pub revocation_reason: Option<String>,
    pub checked_at: String,
}
```

##### `DIDResolutionResponse`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDResolutionResponse {
    pub did: String,
    pub did_document: SimplifiedDIDDocument,
    pub resolved_at: String,
}
```

##### `KeyRotationRequest` / `KeyRotationResponse`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationRequest {
    pub new_public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationResponse {
    pub success: bool,
    pub new_verification_method_id: Option<String>,
    pub transaction_id: Option<String>,
    pub error: Option<String>,
}
```

##### `DIDDeactivationRequest` / `DIDDeactivationResponse`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDDeactivationRequest {
    pub did: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDDeactivationResponse {
    pub success: bool,
    pub transaction_id: Option<String>,
    pub error: Option<String>,
}
```

---

#### Tipi per Autenticazione DID

##### Struct `DIDAuthMessage`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDAuthMessage {
    pub message_type: DIDAuthMessageType,
    pub did: Option<String>,
    pub credential_jwt: Option<String>,
    pub challenge: Option<String>,
    pub signature: Option<String>,
    pub public_key: Option<String>,
    pub error: Option<String>,
}
```

Messaggio generico per il protocollo di autenticazione DID a 4 fasi.

##### Enum `DIDAuthMessageType`

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DIDAuthMessageType {
    Hello,
    Challenge,
    Response,
    Verified,
    Error,
}
```

**Fasi del protocollo**:
1. `Hello`: Client invia DID + credenziale JWT
2. `Challenge`: Server invia challenge random (32 byte)
3. `Response`: Client firma il challenge
4. `Verified`: Server conferma autenticazione

##### Struct `AuthenticationMetrics`

```rust
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthenticationMetrics {
    pub tls_handshake_ms: u64,
    pub did_auth_ms: u64,
    pub credential_verify_ms: u64,
    pub challenge_response_ms: u64,
    pub total_ms: u64,
}
```

Metriche di performance per ogni connessione autenticata.

##### Struct `AggregatedMetrics`

```rust
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AggregatedMetrics {
    pub total_connections: u64,
    pub successful_connections: u64,
    pub failed_connections: u64,
    pub avg_tls_handshake_ms: f64,
    pub avg_did_auth_ms: f64,
    pub avg_credential_verify_ms: f64,
    pub avg_challenge_response_ms: f64,
    pub avg_total_ms: f64,
    pub cache_hits: u64,
    pub cache_misses: u64,
}
```

Statistiche aggregate per monitoring.

---

## Crate identity-service/

Il crate `identity-service` implementa il server REST che gestisce identità DID, emissione credenziali e revoca on-chain.

### File: `identity-service/src/lib.rs`

**Scopo**: Definisce lo stato condiviso dell'applicazione e riesporta i moduli.

```rust
pub mod api;
pub mod cache;
pub mod credential;
pub mod did;
pub mod revocation;

use std::sync::Arc;
use shared::config::IdentityServiceConfig;

pub struct AppState {
    pub config: Arc<IdentityServiceConfig>,
    pub did_manager: Arc<did::DIDManager>,
    pub credential_issuer: Arc<credential::CredentialIssuer>,
    pub cache: Arc<cache::CacheManager>,
    pub revocation_manager: Arc<revocation::RevocationManager>,
    pub onchain_revocation_manager: Arc<revocation::OnChainRevocationManager>,
}
```

**Campi di `AppState`**:
- `config`: Configurazione immutabile condivisa
- `did_manager`: Gestisce creazione/risoluzione/rotazione DID on-chain
- `credential_issuer`: Emette e verifica credenziali W3C VC
- `cache`: Sistema di caching a due livelli
- `revocation_manager`: Revoca in-memory (deprecato)
- `onchain_revocation_manager`: Revoca on-chain con RevocationBitmap2022

Tutti i campi sono wrappati in `Arc` per condivisione thread-safe tra gli handler Axum.

---

### File: `identity-service/src/main.rs`

**Scopo**: Entry point del server, inizializzazione componenti.

#### Funzione `main()`

```rust
#[tokio::main]
async fn main() -> Result<()> {
    // 1. Inizializza logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // 2. Carica configurazione da variabili d'ambiente
    let config = IdentityServiceConfig::from_env();
    info!(network = ?config.network, "Starting Identity Service");

    // 3. Inizializza DID Manager (connessione blockchain)
    let did_manager = DIDManager::new(&config).await?;

    // 4. Inizializza Cache Manager
    let cache = CacheManager::new(&config.cache);

    // 5. Inizializza Revocation Managers
    let revocation_manager = RevocationManager::new();
    let onchain_revocation = OnChainRevocationManager::new();

    // 6. Inizializza Credential Issuer
    let credential_issuer = CredentialIssuer::new(
        &config.credential,
        revocation_manager.clone(),
    );

    // 7. Costruisce AppState condiviso
    let state = Arc::new(AppState {
        config: Arc::new(config.clone()),
        did_manager: Arc::new(did_manager),
        credential_issuer: Arc::new(credential_issuer),
        cache: Arc::new(cache),
        revocation_manager: Arc::new(revocation_manager),
        onchain_revocation_manager: Arc::new(onchain_revocation),
    });

    // 8. Crea router Axum
    let app = api::create_router(state);

    // 9. Avvia server
    let addr = config.api.listen_addr();
    let listener = TcpListener::bind(&addr).await?;
    info!(addr = %addr, "Server listening");

    axum::serve(listener, app).await?;
    Ok(())
}
```

**Flusso di inizializzazione**:
1. **Logging**: Usa `tracing_subscriber` con filtro da `RUST_LOG`
2. **Config**: Carica da env vars (`IOTA_NETWORK`, `API_PORT`, etc.)
3. **DIDManager**: Crea connessione IOTA Rebased, carica/crea issuer DID
4. **Cache**: Inizializza cache Moka con TTL configurati
5. **Revocation**: Crea manager per revoca (in-memory e on-chain)
6. **CredentialIssuer**: Prepara chiave di firma Ed25519
7. **AppState**: Combina tutto in stato condiviso Arc
8. **Router**: Configura endpoints REST con Axum
9. **Server**: Bind TCP e avvia server async

---

### File: `identity-service/src/api/mod.rs`

**Scopo**: Definisce tutti gli endpoint REST e i loro handler.

#### Funzione `create_router()`

```rust
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Health check
        .route("/health", get(health_check))

        // Device registration
        .route("/api/v1/device/register", post(register_device))

        // DID operations
        .route("/api/v1/did/resolve/:did", get(resolve_did))
        .route("/api/v1/did/deactivate", post(deactivate_did))
        .route("/api/v1/did/rotate-key/:did", post(rotate_key))

        // Credential operations
        .route("/api/v1/credential/verify", post(verify_credential))
        .route("/api/v1/credential/revoke", post(revoke_credential))

        // On-chain revocation
        .route("/api/v1/revocation/revoke", post(revoke_credential_onchain))
        .route("/api/v1/revocation/status/:credential_id", get(get_credential_status_onchain))
        .route("/api/v1/revocation/stats", get(get_bitmap_stats))

        // Issuer management
        .route("/api/v1/issuer/initialize", post(initialize_issuer_did))
        .route("/api/v1/issuer/status", get(get_issuer_status))

        // Admin
        .route("/api/v1/admin/clear-caches", post(clear_caches))
        .route("/api/v1/metrics", get(get_metrics))

        .with_state(state)
}
```

#### Handler `register_device`

```rust
async fn register_device(
    State(state): State<Arc<AppState>>,
    Json(request): Json<DeviceRegistrationRequest>,
) -> Result<Json<DeviceRegistrationResponse>, ApiError> {
    info!(device_type = ?request.device_type, "Registering device");

    // 1. Crea DID on-chain per il dispositivo
    let (did, object_id) = state.did_manager
        .create_did(&request.public_key)
        .await
        .map_err(ApiError::from)?;

    // 2. Alloca indice nel bitmap di revoca
    let revocation_index = state.onchain_revocation_manager
        .allocate_index()
        .await;

    // 3. Crea credential status (RevocationBitmap2022)
    let credential_status = state.onchain_revocation_manager
        .create_credential_status(&did, revocation_index);

    // 4. Emetti credenziale JWT
    let (credential_jwt, expires_at) = state.credential_issuer
        .issue_credential_jwt(
            &did,
            &request.public_key,
            request.device_type.clone(),
            request.capabilities.clone(),
            Some(credential_status),
        )
        .await
        .map_err(ApiError::from)?;

    // 5. Registra mapping credential -> index
    state.onchain_revocation_manager
        .register_credential(&credential_jwt, revocation_index)
        .await;

    Ok(Json(DeviceRegistrationResponse {
        did,
        object_id,
        credential_jwt,
        credential_expires_at: expires_at,
    }))
}
```

**Flusso logico**:
1. Riceve chiave pubblica Ed25519 hex dal dispositivo
2. Chiama `DIDManager::create_did()` → transazione blockchain → nuovo DID
3. Alloca slot nel RevocationBitmap (AtomicU32 incrementale)
4. Costruisce `CredentialStatus` con URI `did:iota:...#revocation` e indice
5. Genera JWT firmato con Ed25519 dell'issuer
6. Mappa `credential_id` → `revocation_index` per lookup veloce
7. Restituisce DID, object_id, JWT e data scadenza

#### Handler `resolve_did`

```rust
async fn resolve_did(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
) -> Result<Json<DIDResolutionResponse>, ApiError> {
    let did_decoded = urlencoding::decode(&did)
        .map_err(|_| ApiError::BadRequest("Invalid DID encoding".into()))?;

    // Check cache first
    if let Some(cached) = state.cache.get_did(&did_decoded).await {
        return Ok(Json(DIDResolutionResponse {
            did: did_decoded.to_string(),
            did_document: (*cached).clone(),
            resolved_at: chrono::Utc::now().to_rfc3339(),
        }));
    }

    // Resolve from blockchain
    let document = state.did_manager
        .resolve_did(&did_decoded)
        .await
        .map_err(ApiError::from)?;

    let simplified = convert_to_simplified(&document);

    // Cache the result
    state.cache.insert_did(&did_decoded, simplified.clone()).await;

    Ok(Json(DIDResolutionResponse {
        did: did_decoded.to_string(),
        did_document: simplified,
        resolved_at: chrono::Utc::now().to_rfc3339(),
    }))
}
```

#### Handler `verify_credential`

```rust
async fn verify_credential(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CredentialVerificationRequest>,
) -> Result<Json<CredentialVerificationResponse>, ApiError> {
    // 1. Verifica firma JWT
    let result = state.credential_issuer
        .verify_credential(&request.credential_jwt)
        .await;

    match result {
        Ok(metadata) => {
            // 2. Check revocation status on-chain
            let revoked = state.onchain_revocation_manager
                .is_revoked(&metadata.credential_id)
                .await;

            if revoked {
                return Ok(Json(CredentialVerificationResponse {
                    valid: false,
                    subject_did: Some(metadata.subject_did),
                    issuer_did: Some(metadata.issuer_did),
                    error: Some("Credential has been revoked".into()),
                    verified_at: chrono::Utc::now().to_rfc3339(),
                }));
            }

            Ok(Json(CredentialVerificationResponse {
                valid: true,
                subject_did: Some(metadata.subject_did),
                issuer_did: Some(metadata.issuer_did),
                error: None,
                verified_at: chrono::Utc::now().to_rfc3339(),
            }))
        }
        Err(e) => Ok(Json(CredentialVerificationResponse {
            valid: false,
            subject_did: None,
            issuer_did: None,
            error: Some(e.to_string()),
            verified_at: chrono::Utc::now().to_rfc3339(),
        }))
    }
}
```

#### Handler `revoke_credential_onchain`

```rust
async fn revoke_credential_onchain(
    State(state): State<Arc<AppState>>,
    Json(request): Json<OnChainRevocationRequest>,
) -> Result<Json<OnChainRevocationResponse>, ApiError> {
    // 1. Revoca nel bitmap locale
    let result = state.onchain_revocation_manager
        .revoke(&request.credential_id, request.reason.clone())
        .await;

    match result {
        Ok(index) => {
            // 2. Aggiorna servizio di revoca on-chain (DID Document update)
            let bitmap_data = state.onchain_revocation_manager
                .encode_service_endpoint()
                .await;

            let issuer_did = state.credential_issuer.issuer_did().await;

            if let Some(did) = issuer_did {
                // Update DID Document with new bitmap
                let tx_id = state.did_manager
                    .update_revocation_service(&did, &bitmap_data)
                    .await
                    .ok();

                return Ok(Json(OnChainRevocationResponse {
                    success: true,
                    credential_id: request.credential_id,
                    revocation_index: Some(index),
                    transaction_id: tx_id,
                    error: None,
                }));
            }

            Ok(Json(OnChainRevocationResponse {
                success: true,
                credential_id: request.credential_id,
                revocation_index: Some(index),
                transaction_id: None,
                error: None,
            }))
        }
        Err(e) => Ok(Json(OnChainRevocationResponse {
            success: false,
            credential_id: request.credential_id,
            revocation_index: None,
            transaction_id: None,
            error: Some(e.to_string()),
        }))
    }
}
```

#### Handler `rotate_key`

```rust
async fn rotate_key(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
    Json(request): Json<KeyRotationRequest>,
) -> Result<Json<KeyRotationResponse>, ApiError> {
    let did_decoded = urlencoding::decode(&did)?;

    // Esegue rotazione chiave on-chain
    let result = state.did_manager
        .rotate_key(&did_decoded, &request.new_public_key)
        .await;

    match result {
        Ok((method_id, tx_id)) => {
            // Invalida cache
            state.cache.invalidate_did(&did_decoded).await;

            Ok(Json(KeyRotationResponse {
                success: true,
                new_verification_method_id: Some(method_id),
                transaction_id: Some(tx_id),
                error: None,
            }))
        }
        Err(e) => Ok(Json(KeyRotationResponse {
            success: false,
            new_verification_method_id: None,
            transaction_id: None,
            error: Some(e.to_string()),
        }))
    }
}
```

#### Enum `ApiError`

```rust
pub enum ApiError {
    BadRequest(String),
    NotFound(String),
    InternalError(String),
    IdentityError(IdentityError),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            ApiError::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            ApiError::IdentityError(e) => {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}
```

Conversione automatica da `IdentityError` a risposta HTTP.

---

### File: `identity-service/src/cache/mod.rs`

**Scopo**: Gestione cache a due livelli per DID Document e credenziali.

#### Struct `CacheManager`

```rust
pub struct CacheManager {
    /// Cache per DID Document risolti
    did_cache: Cache<String, Arc<SimplifiedDIDDocument>>,

    /// Cache per risultati verifica credenziali
    credential_cache: Cache<String, CredentialCacheEntry>,

    /// Cache per risoluzioni DID (hit tracking)
    resolution_cache: Cache<String, Arc<SimplifiedDIDDocument>>,

    /// Statistiche
    stats: RwLock<CacheStats>,
}
```

**Uso di Moka**:
- `Cache<K, V>`: HashMap async thread-safe con TTL ed eviction LRU
- `Arc<...>`: Condivisione zero-copy dei documenti cached

#### Costruttore

```rust
impl CacheManager {
    pub fn new(config: &CacheConfig) -> Self {
        let did_cache = Cache::builder()
            .max_capacity(config.max_did_documents)
            .time_to_live(Duration::from_secs(config.did_ttl_secs))
            .build();

        let credential_cache = Cache::builder()
            .max_capacity(config.max_credentials)
            .time_to_live(Duration::from_secs(config.credential_ttl_secs))
            .build();

        let resolution_cache = Cache::builder()
            .max_capacity(config.max_did_documents)
            .time_to_live(Duration::from_secs(config.did_ttl_secs))
            .build();

        Self {
            did_cache,
            credential_cache,
            resolution_cache,
            stats: RwLock::new(CacheStats::default()),
        }
    }
}
```

#### Metodi di Accesso

```rust
impl CacheManager {
    pub async fn get_did(&self, did: &str) -> Option<Arc<SimplifiedDIDDocument>> {
        let result = self.did_cache.get(did).await;

        // Update stats
        let mut stats = self.stats.write().await;
        if result.is_some() {
            stats.did_hits += 1;
        } else {
            stats.did_misses += 1;
        }

        result
    }

    pub async fn insert_did(&self, did: &str, doc: SimplifiedDIDDocument) {
        self.did_cache.insert(did.to_string(), Arc::new(doc)).await;
    }

    pub async fn invalidate_did(&self, did: &str) {
        self.did_cache.invalidate(did).await;
    }

    pub async fn get_credential_status(&self, jwt: &str) -> Option<CredentialCacheEntry> {
        self.credential_cache.get(jwt).await
    }

    pub async fn cache_credential_verification(
        &self,
        jwt: &str,
        valid: bool,
        subject_did: Option<String>,
    ) {
        self.credential_cache.insert(
            jwt.to_string(),
            CredentialCacheEntry {
                valid,
                subject_did,
                cached_at: chrono::Utc::now(),
            },
        ).await;
    }

    pub async fn clear_all(&self) {
        self.did_cache.invalidate_all();
        self.credential_cache.invalidate_all();
        self.resolution_cache.invalidate_all();

        // Run pending cleanup tasks
        self.did_cache.run_pending_tasks().await;
        self.credential_cache.run_pending_tasks().await;
        self.resolution_cache.run_pending_tasks().await;
    }
}
```

#### Struct `CacheStats`

```rust
#[derive(Debug, Default)]
pub struct CacheStats {
    pub did_hits: u64,
    pub did_misses: u64,
    pub credential_hits: u64,
    pub credential_misses: u64,
}

impl CacheStats {
    pub fn did_hit_rate(&self) -> f64 {
        let total = self.did_hits + self.did_misses;
        if total == 0 { 0.0 } else { self.did_hits as f64 / total as f64 }
    }
}
```

#### Struct `CachedResolver`

```rust
pub struct CachedResolver {
    cache: Arc<CacheManager>,
    resolver: Arc<dyn Fn(&str) -> BoxFuture<'static, Result<SimplifiedDIDDocument>>>,
}

impl CachedResolver {
    pub async fn resolve(&self, did: &str) -> Result<Arc<SimplifiedDIDDocument>> {
        // Check cache
        if let Some(cached) = self.cache.get_did(did).await {
            return Ok(cached);
        }

        // Resolve and cache
        let doc = (self.resolver)(did).await?;
        self.cache.insert_did(did, doc.clone()).await;

        Ok(Arc::new(doc))
    }
}
```

Wrapper che aggiunge caching trasparente a qualsiasi resolver.

---

### File: `identity-service/src/credential/mod.rs`

**Scopo**: Emissione e verifica di Verifiable Credentials W3C.

#### Struct `CredentialIssuer`

```rust
pub struct CredentialIssuer {
    /// Chiave di firma Ed25519 dell'issuer
    signing_key: ed25519_dalek::SigningKey,

    /// DID dell'issuer (caricato async)
    issuer_did: RwLock<Option<String>>,

    /// Manager revoca per embedding status
    revocation_manager: Arc<RevocationManager>,

    /// Durata validità credenziali
    validity_hours: u64,

    /// Nome issuer per metadata
    issuer_name: String,
}
```

#### Costruttore

```rust
impl CredentialIssuer {
    pub fn new(
        config: &CredentialConfig,
        revocation_manager: Arc<RevocationManager>,
    ) -> Self {
        // Genera nuova chiave o carica esistente
        let signing_key = Self::load_or_generate_key();

        Self {
            signing_key,
            issuer_did: RwLock::new(None),
            revocation_manager,
            validity_hours: config.validity_hours,
            issuer_name: config.issuer_name.clone(),
        }
    }

    fn load_or_generate_key() -> SigningKey {
        let key_path = Path::new("./data/issuer_key.hex");

        if key_path.exists() {
            let hex = std::fs::read_to_string(key_path).unwrap();
            let bytes: [u8; 32] = hex::decode(hex.trim())
                .unwrap()
                .try_into()
                .unwrap();
            SigningKey::from_bytes(&bytes)
        } else {
            let key = SigningKey::generate(&mut OsRng);
            std::fs::create_dir_all("./data").ok();
            std::fs::write(key_path, hex::encode(key.to_bytes())).unwrap();
            key
        }
    }
}
```

#### Metodo `issue_credential_jwt`

```rust
impl CredentialIssuer {
    pub async fn issue_credential_jwt(
        &self,
        subject_did: &str,
        public_key: &str,
        device_type: DeviceType,
        capabilities: Vec<String>,
        credential_status: Option<CredentialStatus>,
    ) -> Result<(String, String)> {
        let issuer_did = self.issuer_did.read().await
            .clone()
            .ok_or_else(|| anyhow!("Issuer DID not initialized"))?;

        let now = chrono::Utc::now();
        let expires = now + chrono::Duration::hours(self.validity_hours as i64);

        // 1. Costruisci credenziale
        let credential = DeviceCredential {
            context: vec![
                CREDENTIAL_CONTEXT.to_string(),
                "https://w3id.org/security/suites/ed25519-2020/v1".to_string(),
            ],
            id: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            credential_type: vec![
                "VerifiableCredential".to_string(),
                IOT_CREDENTIAL_TYPE.to_string(),
            ],
            issuer: issuer_did.clone(),
            issuance_date: now.to_rfc3339(),
            expiration_date: Some(expires.to_rfc3339()),
            credential_subject: CredentialSubject {
                id: subject_did.to_string(),
                device_type,
                capabilities,
                public_key: public_key.to_string(),
            },
            credential_status,
            proof: None, // Aggiunta dopo per JWT
        };

        // 2. Serializza in JSON
        let payload = serde_json::to_value(&credential)?;

        // 3. Crea header JWT
        let header = json!({
            "alg": "EdDSA",
            "typ": "JWT",
            "kid": format!("{}#key-1", issuer_did)
        });

        // 4. Codifica Base64URL
        let header_b64 = base64_url_encode(&serde_json::to_vec(&header)?);
        let payload_b64 = base64_url_encode(&serde_json::to_vec(&payload)?);

        // 5. Firma con Ed25519
        let message = format!("{}.{}", header_b64, payload_b64);
        let signature = self.signing_key.sign(message.as_bytes());
        let signature_b64 = base64_url_encode(&signature.to_bytes());

        // 6. Assembla JWT
        let jwt = format!("{}.{}.{}", header_b64, payload_b64, signature_b64);

        Ok((jwt, expires.to_rfc3339()))
    }
}
```

**Flusso**:
1. Verifica che l'issuer DID sia inizializzato
2. Calcola timestamp emissione e scadenza
3. Costruisce struttura `DeviceCredential` W3C compliant
4. Serializza in JSON il payload
5. Crea header JWT con algoritmo EdDSA
6. Codifica header e payload in Base64URL
7. Firma `header.payload` con chiave Ed25519
8. Restituisce JWT completo e data scadenza

#### Metodo `verify_credential`

```rust
impl CredentialIssuer {
    pub async fn verify_credential(
        &self,
        jwt: &str,
    ) -> Result<CredentialMetadata> {
        // 1. Split JWT in parti
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(anyhow!("Invalid JWT format"));
        }

        let header_b64 = parts[0];
        let payload_b64 = parts[1];
        let signature_b64 = parts[2];

        // 2. Decodifica header
        let header: serde_json::Value = serde_json::from_slice(
            &base64_url_decode(header_b64)?
        )?;

        // 3. Verifica algoritmo
        if header["alg"] != "EdDSA" {
            return Err(anyhow!("Unsupported algorithm"));
        }

        // 4. Decodifica payload
        let payload: DeviceCredential = serde_json::from_slice(
            &base64_url_decode(payload_b64)?
        )?;

        // 5. Verifica issuer
        let issuer_did = self.issuer_did.read().await;
        if issuer_did.as_ref() != Some(&payload.issuer) {
            return Err(anyhow!("Unknown issuer"));
        }

        // 6. Verifica firma
        let message = format!("{}.{}", header_b64, payload_b64);
        let signature_bytes = base64_url_decode(signature_b64)?;
        let signature = Signature::from_slice(&signature_bytes)?;

        self.signing_key
            .verifying_key()
            .verify(message.as_bytes(), &signature)?;

        // 7. Verifica scadenza
        if let Some(ref exp) = payload.expiration_date {
            let exp_time = chrono::DateTime::parse_from_rfc3339(exp)?;
            if exp_time < chrono::Utc::now() {
                return Err(anyhow!("Credential expired"));
            }
        }

        Ok(CredentialMetadata {
            credential_id: payload.id,
            subject_did: payload.credential_subject.id,
            issuer_did: payload.issuer,
            expires_at: payload.expiration_date,
        })
    }
}
```

#### Struct `CredentialMetadata`

```rust
pub struct CredentialMetadata {
    pub credential_id: String,
    pub subject_did: String,
    pub issuer_did: String,
    pub expires_at: Option<String>,
}
```

Informazioni estratte da una credenziale verificata con successo.

---

### File: `identity-service/src/did/mod.rs`

**Scopo**: Gestione completa del ciclo di vita DID su IOTA Rebased blockchain.

#### Struct `DIDManager`

```rust
pub struct DIDManager {
    /// Client read-only per query blockchain
    read_only_client: IdentityClientReadOnly,

    /// Storage per chiavi e documenti (JwkMemStore + KeyIdMemstore)
    storage: IdentityStorage<JwkMemStore, KeyIdMemStore>,

    /// DID dell'issuer (caricato da file o creato)
    issuer_did: RwLock<Option<String>>,

    /// Key ID per transazioni issuer
    issuer_tx_key_id: RwLock<Option<KeyId>>,

    /// JWK pubblica dell'issuer per firma
    issuer_tx_public_jwk: RwLock<Option<Jwk>>,

    /// Informazioni di controllo per ogni DID gestito
    did_control_info: RwLock<HashMap<String, DIDControlInfo>>,

    /// Endpoint blockchain
    endpoint: String,
}
```

**Campi**:
- `read_only_client`: Client IOTA per query (non richiede chiavi)
- `storage`: Combinazione di `JwkMemStore` (chiavi JWK in memoria) e `KeyIdMemStore` (mapping ID)
- `issuer_did`: DID dell'issuer del servizio
- `issuer_tx_key_id`: ID della chiave per firmare transazioni
- `issuer_tx_public_jwk`: Chiave pubblica JWK per verifica
- `did_control_info`: Mappa DID → info per operazioni (rotazione, deattivazione)
- `endpoint`: URL del nodo IOTA Rebased

#### Struct `DIDControlInfo`

```rust
pub struct DIDControlInfo {
    pub object_id: String,
    pub tx_key_id: KeyId,
    pub tx_public_jwk: Jwk,
}
```

Informazioni necessarie per controllare un DID (modifiche on-chain).

#### Costruttore `new()`

```rust
impl DIDManager {
    pub async fn new(config: &IdentityServiceConfig) -> Result<Self> {
        let endpoint = config.custom_endpoint
            .as_deref()
            .unwrap_or_else(|| config.network.endpoint());

        info!(endpoint = %endpoint, "Connecting to IOTA Rebased");

        // 1. Crea client IOTA
        let iota_client = IotaClientBuilder::default()
            .build(endpoint)
            .await
            .context("Failed to build IOTA client")?;

        // 2. Crea client identity read-only
        let read_only_client = IdentityClientReadOnly::new(iota_client)
            .await
            .context("Failed to create identity client")?;

        // 3. Setup storage in-memory
        let storage = IdentityStorage::new(
            JwkMemStore::new(),
            KeyIdMemStore::new(),
        );

        let mut manager = Self {
            read_only_client,
            storage,
            issuer_did: RwLock::new(None),
            issuer_tx_key_id: RwLock::new(None),
            issuer_tx_public_jwk: RwLock::new(None),
            did_control_info: RwLock::new(HashMap::new()),
            endpoint: endpoint.to_string(),
        };

        // 4. Carica o crea issuer DID
        manager.load_or_create_issuer().await?;

        Ok(manager)
    }
}
```

#### Metodo `create_did()`

```rust
impl DIDManager {
    pub async fn create_did(&self, public_key_hex: &str) -> Result<(String, String)> {
        info!(public_key = %&public_key_hex[..16], "Creating new DID");

        // 1. Decodifica chiave pubblica da hex
        let public_key_bytes = hex::decode(public_key_hex)
            .context("Invalid public key hex")?;

        // 2. Crea JWK Ed25519 dalla chiave pubblica
        let jwk = create_ed25519_jwk_from_bytes(&public_key_bytes)?;

        // 3. Prepara client con capacità di scrittura
        let iota_client = IotaClientBuilder::default()
            .build(&self.endpoint)
            .await?;

        // 4. Usa le chiavi dell'issuer per pagare il gas
        let issuer_key_id = self.issuer_tx_key_id.read().await
            .clone()
            .ok_or_else(|| anyhow!("Issuer not initialized"))?;

        let issuer_jwk = self.issuer_tx_public_jwk.read().await
            .clone()
            .ok_or_else(|| anyhow!("Issuer JWK not available"))?;

        // 5. Crea signer per transazioni
        let signer = StorageSigner::new(&self.storage, issuer_key_id.clone(), issuer_jwk);

        // 6. Crea client con capacità di scrittura
        let identity_client = IdentityClient::new(iota_client, signer)
            .await
            .context("Failed to create identity client")?;

        // 7. Crea nuovo DID Document
        let mut document = IotaDocument::new(identity_client.network());

        // 8. Aggiungi verification method con la chiave del dispositivo
        let method = IotaVerificationMethod::new_from_jwk(
            document.id().clone(),
            jwk.clone(),
            Some("key-1"),
        )?;
        document.insert_method(method, MethodScope::VerificationMethod)?;

        // 9. Pubblica on-chain
        let output = identity_client
            .publish_did_document(&document)
            .with_gas_budget(DID_CREATION_GAS)
            .finish()
            .await
            .context("Failed to publish DID document")?;

        let did = document.id().to_string();
        let object_id = output.object_id().to_string();

        info!(did = %did, object_id = %object_id, "DID created on-chain");

        // 10. Salva control info per operazioni future
        let control_info = DIDControlInfo {
            object_id: object_id.clone(),
            tx_key_id: issuer_key_id,
            tx_public_jwk: issuer_jwk,
        };

        self.did_control_info.write().await
            .insert(did.clone(), control_info);

        Ok((did, object_id))
    }
}
```

**Flusso**:
1. Decodifica hex → bytes della chiave pubblica Ed25519
2. Converte in formato JWK (JSON Web Key)
3. Crea client IOTA con capacità di scrittura
4. Recupera chiavi dell'issuer per pagare gas
5. Crea `StorageSigner` per firmare transazioni
6. Crea client identity completo
7. Genera nuovo `IotaDocument` per la rete corrente
8. Aggiunge verification method con chiave dispositivo
9. Pubblica transazione on-chain (spende gas)
10. Salva info per future operazioni sul DID

#### Metodo `resolve_did()`

```rust
impl DIDManager {
    pub async fn resolve_did(&self, did: &str) -> Result<IotaDocument> {
        let iota_did = IotaDID::parse(did)
            .context("Invalid DID format")?;

        self.read_only_client
            .resolve_did(&iota_did)
            .await
            .context("DID resolution failed")
    }
}
```

Usa il client read-only per risolvere DID senza spendere gas.

#### Metodo `rotate_key()`

```rust
impl DIDManager {
    pub async fn rotate_key(
        &self,
        did: &str,
        new_public_key_hex: &str,
    ) -> Result<(String, String)> {
        info!(did = %did, "Rotating key");

        // 1. Recupera control info
        let control_info = self.did_control_info.read().await
            .get(did)
            .cloned()
            .ok_or_else(|| anyhow!("DID not under control"))?;

        // 2. Risolvi documento corrente
        let mut document = self.resolve_did(did).await?;

        // 3. Crea nuova JWK dalla chiave
        let new_key_bytes = hex::decode(new_public_key_hex)?;
        let new_jwk = create_ed25519_jwk_from_bytes(&new_key_bytes)?;

        // 4. Genera nuovo method ID
        let method_id = format!("{}#key-{}", did, chrono::Utc::now().timestamp());

        // 5. Crea e aggiungi nuovo verification method
        let new_method = IotaVerificationMethod::new_from_jwk(
            document.id().clone(),
            new_jwk,
            Some(&method_id.split('#').last().unwrap()),
        )?;
        document.insert_method(new_method, MethodScope::VerificationMethod)?;

        // 6. Crea client per transazione
        let iota_client = IotaClientBuilder::default()
            .build(&self.endpoint)
            .await?;

        let signer = StorageSigner::new(
            &self.storage,
            control_info.tx_key_id,
            control_info.tx_public_jwk,
        );

        let identity_client = IdentityClient::new(iota_client, signer).await?;

        // 7. Aggiorna documento on-chain
        let output = identity_client
            .publish_did_document_update(&document)
            .with_gas_budget(KEY_ROTATION_GAS)
            .finish()
            .await?;

        let tx_id = output.transaction_id().to_string();

        info!(did = %did, method_id = %method_id, "Key rotated");

        Ok((method_id, tx_id))
    }
}
```

#### Metodo `deactivate_did()`

```rust
impl DIDManager {
    pub async fn deactivate_did(&self, did: &str) -> Result<String> {
        info!(did = %did, "Deactivating DID");

        let control_info = self.did_control_info.read().await
            .get(did)
            .cloned()
            .ok_or_else(|| anyhow!("DID not under control"))?;

        // Risolvi e modifica documento
        let mut document = self.resolve_did(did).await?;

        // Rimuovi tutti i verification methods (deattivazione)
        let methods: Vec<_> = document.methods(None)
            .map(|m| m.id().clone())
            .collect();

        for method_id in methods {
            document.remove_method(&method_id)?;
        }

        // Pubblica aggiornamento
        let iota_client = IotaClientBuilder::default()
            .build(&self.endpoint)
            .await?;

        let signer = StorageSigner::new(
            &self.storage,
            control_info.tx_key_id,
            control_info.tx_public_jwk,
        );

        let identity_client = IdentityClient::new(iota_client, signer).await?;

        let output = identity_client
            .publish_did_document_update(&document)
            .with_gas_budget(DEFAULT_GAS_BUDGET)
            .finish()
            .await?;

        // Rimuovi da control info
        self.did_control_info.write().await.remove(did);

        Ok(output.transaction_id().to_string())
    }
}
```

#### Metodo `update_revocation_service()`

```rust
impl DIDManager {
    pub async fn update_revocation_service(
        &self,
        did: &str,
        bitmap_data: &str,
    ) -> Result<String> {
        let control_info = self.did_control_info.read().await
            .get(did)
            .cloned()
            .ok_or_else(|| anyhow!("DID not under control"))?;

        let mut document = self.resolve_did(did).await?;

        // Crea o aggiorna servizio RevocationBitmap2022
        let service_id = format!("{}#revocation", did);

        // Rimuovi servizio esistente se presente
        if let Ok(existing) = DIDUrl::parse(&service_id) {
            document.remove_service(&existing).ok();
        }

        // Aggiungi nuovo servizio con bitmap aggiornato
        let service = Service::builder(Default::default())
            .id(DIDUrl::parse(&service_id)?)
            .type_("RevocationBitmap2022")
            .service_endpoint(ServiceEndpoint::One(Url::parse(&format!(
                "data:application/octet-stream;base64,{}",
                bitmap_data
            ))?))
            .build()?;

        document.insert_service(service)?;

        // Pubblica aggiornamento
        let iota_client = IotaClientBuilder::default()
            .build(&self.endpoint)
            .await?;

        let signer = StorageSigner::new(
            &self.storage,
            control_info.tx_key_id,
            control_info.tx_public_jwk,
        );

        let identity_client = IdentityClient::new(iota_client, signer).await?;

        let output = identity_client
            .publish_did_document_update(&document)
            .with_gas_budget(REVOCATION_GAS)
            .finish()
            .await?;

        Ok(output.transaction_id().to_string())
    }
}
```

#### Funzione Helper `create_ed25519_jwk_from_bytes()`

```rust
fn create_ed25519_jwk_from_bytes(public_key_bytes: &[u8]) -> Result<Jwk> {
    use base64::Engine;

    // Ed25519 usa chiavi da 32 byte
    if public_key_bytes.len() != 32 {
        return Err(anyhow!("Ed25519 public key must be 32 bytes"));
    }

    // Codifica in base64url (no padding)
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(public_key_bytes);

    // Costruisci JWK OKP (Octet Key Pair)
    let jwk = Jwk::from_params(JwkParamsOkp {
        kty: JwkType::Okp,
        crv: "Ed25519".to_string(),
        x,
        d: None, // No private key
    });

    Ok(jwk)
}
```

---

### File: `identity-service/src/revocation/mod.rs`

**Scopo**: Revoca in-memory (legacy, per testing).

#### Struct `RevocationManager`

```rust
pub struct RevocationManager {
    /// Mappa credential_id -> entry revoca
    revoked: RwLock<HashMap<String, RevocationEntry>>,
}

#[derive(Clone)]
pub struct RevocationEntry {
    pub credential_id: String,
    pub revoked_at: chrono::DateTime<chrono::Utc>,
    pub reason: Option<String>,
}
```

#### Metodi

```rust
impl RevocationManager {
    pub fn new() -> Self {
        Self {
            revoked: RwLock::new(HashMap::new()),
        }
    }

    pub async fn revoke(&self, credential_id: &str, reason: Option<String>) -> Result<()> {
        let entry = RevocationEntry {
            credential_id: credential_id.to_string(),
            revoked_at: chrono::Utc::now(),
            reason,
        };

        self.revoked.write().await
            .insert(credential_id.to_string(), entry);

        Ok(())
    }

    pub async fn is_revoked(&self, credential_id: &str) -> bool {
        self.revoked.read().await.contains_key(credential_id)
    }

    pub async fn unrevoke(&self, credential_id: &str) -> bool {
        self.revoked.write().await.remove(credential_id).is_some()
    }
}
```

---

### File: `identity-service/src/revocation/bitmap.rs`

**Scopo**: Implementazione RevocationBitmap2022 con Roaring Bitmap per revoca on-chain efficiente.

#### Struct `OnChainRevocationManager`

```rust
pub struct OnChainRevocationManager {
    /// Roaring Bitmap per indici revocati
    bitmap: RwLock<RoaringBitmap>,

    /// Prossimo indice da allocare
    next_index: AtomicU32,

    /// Mapping credential_id -> revocation_index
    credential_to_index: RwLock<HashMap<String, u32>>,

    /// Mapping index -> reason
    revocation_reasons: RwLock<HashMap<u32, String>>,

    /// Flag per indicare modifiche non pubblicate
    dirty: AtomicBool,
}
```

**Campi**:
- `bitmap`: Roaring Bitmap compressa per O(1) lookup revoca
- `next_index`: Contatore atomico per assegnazione indici
- `credential_to_index`: Reverse lookup credential → indice
- `revocation_reasons`: Motivazioni revoca opzionali
- `dirty`: Indica se il bitmap locale è diverso da on-chain

#### Costruttore

```rust
impl OnChainRevocationManager {
    pub fn new() -> Self {
        Self {
            bitmap: RwLock::new(RoaringBitmap::new()),
            next_index: AtomicU32::new(0),
            credential_to_index: RwLock::new(HashMap::new()),
            revocation_reasons: RwLock::new(HashMap::new()),
            dirty: AtomicBool::new(false),
        }
    }
}
```

#### Metodo `allocate_index()`

```rust
impl OnChainRevocationManager {
    pub async fn allocate_index(&self) -> u32 {
        // Atomically increment and return previous value
        self.next_index.fetch_add(1, Ordering::SeqCst)
    }
}
```

Assegna indici in modo thread-safe per credenziali concorrenti.

#### Metodo `create_credential_status()`

```rust
impl OnChainRevocationManager {
    pub fn create_credential_status(
        &self,
        issuer_did: &str,
        index: u32,
    ) -> CredentialStatus {
        CredentialStatus {
            id: format!("{}#revocation", issuer_did),
            status_type: "RevocationBitmap2022".to_string(),
            revocation_bitmap_index: Some(index.to_string()),
        }
    }
}
```

Crea la struttura `credentialStatus` per embedding nella credenziale.

#### Metodo `register_credential()`

```rust
impl OnChainRevocationManager {
    pub async fn register_credential(&self, credential_id: &str, index: u32) {
        self.credential_to_index.write().await
            .insert(credential_id.to_string(), index);
    }
}
```

#### Metodo `revoke()`

```rust
impl OnChainRevocationManager {
    pub async fn revoke(
        &self,
        credential_id: &str,
        reason: Option<String>,
    ) -> Result<u32, OnChainRevocationError> {
        // 1. Trova l'indice della credenziale
        let index = self.credential_to_index.read().await
            .get(credential_id)
            .copied()
            .ok_or_else(|| OnChainRevocationError::CredentialNotFound(
                credential_id.to_string()
            ))?;

        // 2. Verifica non già revocata
        if self.bitmap.read().await.contains(index) {
            return Err(OnChainRevocationError::AlreadyRevoked(
                credential_id.to_string()
            ));
        }

        // 3. Imposta bit nel bitmap
        self.bitmap.write().await.insert(index);

        // 4. Salva reason se fornita
        if let Some(r) = reason {
            self.revocation_reasons.write().await.insert(index, r);
        }

        // 5. Marca come dirty
        self.dirty.store(true, Ordering::SeqCst);

        info!(credential_id = %credential_id, index = index, "Credential revoked");

        Ok(index)
    }
}
```

#### Metodo `is_revoked()`

```rust
impl OnChainRevocationManager {
    pub async fn is_revoked(&self, credential_id: &str) -> bool {
        if let Some(index) = self.credential_to_index.read().await.get(credential_id) {
            self.bitmap.read().await.contains(*index)
        } else {
            false
        }
    }

    pub async fn is_revoked_by_index(&self, index: u32) -> bool {
        self.bitmap.read().await.contains(index)
    }
}
```

#### Metodo `encode_service_endpoint()`

```rust
impl OnChainRevocationManager {
    pub async fn encode_service_endpoint(&self) -> String {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use std::io::Write;

        let bitmap = self.bitmap.read().await;

        // 1. Serializza bitmap in bytes
        let mut bitmap_bytes = Vec::new();
        bitmap.serialize_into(&mut bitmap_bytes).unwrap();

        // 2. Comprimi con ZLIB
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&bitmap_bytes).unwrap();
        let compressed = encoder.finish().unwrap();

        // 3. Codifica in Base64
        base64::engine::general_purpose::STANDARD.encode(&compressed)
    }
}
```

**Formato RevocationBitmap2022**:
1. Roaring Bitmap → bytes serializzati
2. ZLIB compression → dimensione ridotta
3. Base64 encoding → stringa per service endpoint

#### Metodo `decode_service_endpoint()`

```rust
impl OnChainRevocationManager {
    pub fn decode_service_endpoint(data: &str) -> Result<RoaringBitmap> {
        use flate2::read::ZlibDecoder;
        use std::io::Read;

        // 1. Decodifica Base64
        let compressed = base64::engine::general_purpose::STANDARD
            .decode(data)?;

        // 2. Decomprimi ZLIB
        let mut decoder = ZlibDecoder::new(&compressed[..]);
        let mut bitmap_bytes = Vec::new();
        decoder.read_to_end(&mut bitmap_bytes)?;

        // 3. Deserializza Roaring Bitmap
        let bitmap = RoaringBitmap::deserialize_from(&bitmap_bytes[..])?;

        Ok(bitmap)
    }
}
```

#### Metodo `check_revocation_status()`

```rust
impl OnChainRevocationManager {
    pub async fn check_revocation_status(
        &self,
        credential_id: &str,
    ) -> CredentialStatusResponse {
        let revoked = self.is_revoked(credential_id).await;

        let (index, reason) = if revoked {
            let idx = self.credential_to_index.read().await
                .get(credential_id)
                .copied();
            let rsn = idx.and_then(|i| {
                // This would need async but simplified here
                None
            });
            (idx, rsn)
        } else {
            (None, None)
        };

        CredentialStatusResponse {
            credential_id: credential_id.to_string(),
            revoked,
            revocation_index: index,
            revocation_reason: reason,
            checked_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}
```

#### Struct `RevocationBitmapStats`

```rust
pub struct RevocationBitmapStats {
    pub total_credentials: u32,
    pub revoked_count: u64,
    pub bitmap_size_bytes: usize,
    pub compression_ratio: f64,
}

impl OnChainRevocationManager {
    pub async fn stats(&self) -> RevocationBitmapStats {
        let bitmap = self.bitmap.read().await;
        let total = self.next_index.load(Ordering::SeqCst);
        let revoked = bitmap.len();

        let mut raw_bytes = Vec::new();
        bitmap.serialize_into(&mut raw_bytes).ok();

        let encoded = self.encode_service_endpoint().await;
        let compressed_size = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .map(|b| b.len())
            .unwrap_or(0);

        RevocationBitmapStats {
            total_credentials: total,
            revoked_count: revoked,
            bitmap_size_bytes: compressed_size,
            compression_ratio: if raw_bytes.is_empty() {
                0.0
            } else {
                compressed_size as f64 / raw_bytes.len() as f64
            },
        }
    }
}
```

#### Enum `OnChainRevocationError`

```rust
#[derive(Debug, Clone)]
pub enum OnChainRevocationError {
    CredentialNotFound(String),
    AlreadyRevoked(String),
    DecodingError(String),
    EncodingError(String),
}
```

---

## Crate device-client/

Il crate `device-client` implementa il client CLI per dispositivi IoT con supporto TLS e autenticazione DID.

### File: `device-client/src/lib.rs`

**Scopo**: Entry point del crate, espone API pubbliche.

```rust
mod identity;
mod registration;
mod resolver;
mod storage;
mod tls;

pub use identity::IdentityManager;
pub use registration::DeviceRegistrar;
pub use resolver::DIDResolver;
pub use storage::SecureStorage;
pub use tls::{TlsClient, TlsServer, AuthenticatedConnection};
pub use tls::verifier::CredentialVerifier;
```

---

### File: `device-client/src/main.rs`

**Scopo**: CLI per gestione dispositivo IoT.

#### Struttura CLI

```rust
#[derive(Parser)]
#[command(name = "device-client")]
#[command(about = "IOTA IoT Device Client with DID Authentication")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long, default_value = "http://localhost:8080")]
    identity_service: String,

    #[arg(long, default_value = "testnet")]
    network: String,

    #[arg(long, default_value = "./device-data")]
    data_dir: String,
}

#[derive(Subcommand)]
enum Commands {
    Register { device_type: String, capabilities: String },
    Reregister { device_type: String, capabilities: String },
    Show,
    Sign { message: String },
    Connect { addr: String, repeat: usize, repeat_delay_ms: u64 },
    Server { port: u16 },
    Resolve { did: String },
    Clear,
    RotateKey,
}
```

**Comandi disponibili**:
- `register`: Registra nuovo dispositivo con Identity Service
- `reregister`: Forza ri-registrazione (nuova identità)
- `show`: Mostra identità corrente
- `sign`: Firma messaggio con chiave privata
- `connect`: Connetti a dispositivo remoto via TLS+DID
- `server`: Avvia server TLS per accettare connessioni
- `resolve`: Risolvi DID da blockchain
- `clear`: Cancella tutti i dati locali
- `rotate-key`: Ruota chiave crittografica on-chain

#### Funzione `connect_to_device()`

```rust
async fn connect_to_device(
    config: &DeviceClientConfig,
    addr: &str,
    repeat: usize,
    repeat_delay_ms: u64,
) -> Result<()> {
    // 1. Carica identity manager
    let manager = IdentityManager::new(config).await?;

    if !manager.is_initialized() {
        println!("Device not registered. Run 'register' first.");
        return Ok(());
    }

    // 2. Estrai credenziali
    let did = manager.did().unwrap().to_string();
    let credential_jwt = manager.credential_jwt().unwrap().to_string();
    let signing_key = manager.signing_key().unwrap().clone();

    // 3. Crea resolver DID
    let resolver = Arc::new(DIDResolver::new(config).await?);

    // 4. Crea client TLS
    let client = TlsClient::new(
        resolver,
        did,
        credential_jwt,
        signing_key,
        config.identity_service_url.clone(),
        config.tls.clone(),
    )?;

    // 5. Loop connessioni (per benchmark)
    for i in 0..repeat {
        if i > 0 {
            tokio::time::sleep(Duration::from_millis(repeat_delay_ms)).await;
        }

        match client.connect(addr).await {
            Ok(connection) => {
                println!("Connected! Peer DID: {}", connection.peer_did);
                println!("Metrics:");
                println!("  TLS Handshake: {}ms", connection.metrics.tls_handshake_ms);
                println!("  DID Auth: {}ms", connection.metrics.did_auth_ms);
                println!("  Total: {}ms", connection.metrics.total_ms);

                // Keep alive briefly
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(e) => println!("Connection failed: {}", e),
        }
    }

    Ok(())
}
```

#### Funzione `start_server()`

```rust
async fn start_server(config: &DeviceClientConfig, port: u16) -> Result<()> {
    let manager = IdentityManager::new(config).await?;

    if !manager.is_initialized() {
        println!("Device not registered. Run 'register' first.");
        return Ok(());
    }

    let did = manager.did().unwrap().to_string();
    let credential_jwt = manager.credential_jwt().unwrap().to_string();
    let signing_key = manager.signing_key().unwrap().clone();

    let resolver = Arc::new(DIDResolver::new(config).await?);

    let server = TlsServer::new(
        resolver,
        did.clone(),
        credential_jwt,
        signing_key,
        config.identity_service_url.clone(),
        config.tls.clone(),
    )?;

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    println!("Server listening on port {}", port);
    println!("DID: {}", did);

    loop {
        let (stream, addr) = listener.accept().await?;
        info!(peer = %addr, "New connection");

        match server.accept(stream).await {
            Ok(connection) => {
                println!("Authenticated client: {}", connection.peer_did);
            }
            Err(e) => {
                println!("Authentication failed: {}", e);
            }
        }
    }
}
```

#### Funzione `rotate_key()`

```rust
async fn rotate_key(config: &DeviceClientConfig) -> Result<()> {
    let storage = SecureStorage::new(&config.storage).await?;

    let identity = storage.load_identity().await?
        .ok_or_else(|| anyhow!("No device identity found"))?;

    let did = identity.did.clone();

    // 1. Genera nuova coppia di chiavi Ed25519
    let new_signing_key = SigningKey::generate(&mut OsRng);
    let new_public_key_hex = hex::encode(new_signing_key.verifying_key().as_bytes());
    let new_private_key_hex = hex::encode(new_signing_key.to_bytes());

    // 2. Scrivi chiave temporanea (crash safety)
    let tmp_key_path = config.storage.data_path.join("private_key.hex.new");
    let key_path = config.storage.data_path.join("private_key.hex");
    std::fs::write(&tmp_key_path, &new_private_key_hex)?;

    // 3. Chiama Identity Service per rotazione on-chain
    let client = reqwest::Client::new();
    let url = format!(
        "{}/api/v1/did/rotate-key/{}",
        config.identity_service_url,
        urlencoding::encode(&did)
    );

    let response = client
        .post(&url)
        .json(&KeyRotationRequest {
            new_public_key: new_public_key_hex.clone(),
        })
        .send()
        .await?;

    if !response.status().is_success() {
        std::fs::remove_file(&tmp_key_path).ok();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!("Key rotation failed: {}", body));
    }

    let result: KeyRotationResponse = response.json().await?;

    if !result.success {
        std::fs::remove_file(&tmp_key_path).ok();
        return Err(anyhow!("Key rotation failed: {}",
            result.error.unwrap_or_else(|| "Unknown".into())));
    }

    // 4. Rotazione riuscita, sostituisci chiave locale
    std::fs::rename(&tmp_key_path, &key_path)?;

    println!("Key rotated successfully!");
    println!("New verification method: {:?}", result.new_verification_method_id);

    Ok(())
}
```

---

### File: `device-client/src/identity/mod.rs`

**Scopo**: Gestione identità locale del dispositivo.

#### Struct `IdentityManager`

```rust
pub struct IdentityManager {
    storage: SecureStorage,
    signing_key: Option<SigningKey>,
    identity: Option<DeviceIdentity>,
    credential_jwt: Option<String>,
    credential_expires: Option<chrono::DateTime<chrono::Utc>>,
}
```

#### Metodi di Accesso

```rust
impl IdentityManager {
    pub fn is_initialized(&self) -> bool {
        self.identity.is_some() && self.signing_key.is_some()
    }

    pub fn did(&self) -> Option<&str> {
        self.identity.as_ref().map(|i| i.did.as_str())
    }

    pub fn credential_jwt(&self) -> Option<&str> {
        self.credential_jwt.as_deref()
    }

    pub fn signing_key(&self) -> Option<&SigningKey> {
        self.signing_key.as_ref()
    }

    pub fn public_key_hex(&self) -> Option<String> {
        self.signing_key.as_ref()
            .map(|k| hex::encode(k.verifying_key().as_bytes()))
    }

    pub fn is_credential_expired(&self) -> bool {
        self.credential_expires
            .map(|exp| exp < chrono::Utc::now())
            .unwrap_or(true)
    }
}
```

#### Metodo `sign_challenge()`

```rust
impl IdentityManager {
    pub fn sign_challenge(&self, challenge: &str) -> Result<String> {
        let key = self.signing_key.as_ref()
            .ok_or_else(|| anyhow!("No signing key available"))?;

        let signature = key.sign(challenge.as_bytes());
        Ok(hex::encode(signature.to_bytes()))
    }
}
```

---

### File: `device-client/src/registration/mod.rs`

**Scopo**: Registrazione dispositivo con Identity Service.

#### Struct `DeviceRegistrar`

```rust
pub struct DeviceRegistrar {
    identity_service_url: String,
    http_client: reqwest::Client,
    storage: SecureStorage,
    signing_key: Option<SigningKey>,
}
```

#### Metodo `register()`

```rust
impl DeviceRegistrar {
    pub async fn register(
        &mut self,
        device_type: DeviceType,
        capabilities: Vec<String>,
    ) -> Result<DeviceRegistrationResponse> {
        // 1. Genera coppia chiavi Ed25519
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key_hex = hex::encode(signing_key.verifying_key().as_bytes());
        let private_key_hex = hex::encode(signing_key.to_bytes());

        // 2. Chiama Identity Service
        let request = DeviceRegistrationRequest {
            public_key: public_key_hex.clone(),
            device_type: device_type.clone(),
            capabilities: capabilities.clone(),
        };

        let response = self.http_client
            .post(format!("{}/api/v1/device/register", self.identity_service_url))
            .json(&request)
            .send()
            .await?;

        let result: DeviceRegistrationResponse = response.json().await?;

        // 3. Salva localmente
        self.storage.store_private_key(&private_key_hex).await?;
        self.storage.store_identity(DeviceIdentity::new(
            result.did.clone(),
            result.object_id.clone(),
            public_key_hex,
            device_type,
            capabilities,
        )).await?;
        self.storage.store_credential_jwt(&result.credential_jwt).await?;

        Ok(result)
    }
}
```

---

### File: `device-client/src/resolver/mod.rs`

**Scopo**: Risoluzione DID con caching locale.

#### Struct `DIDResolver`

```rust
pub struct DIDResolver {
    identity_client: IdentityClientReadOnly,
    cache: Cache<String, Arc<SimplifiedDIDDocument>>,
    identity_service_url: String,
    http_client: reqwest::Client,
}
```

#### Strategia di Risoluzione

1. **Cache Check**: O(1) lookup in Moka cache
2. **Blockchain Query**: Diretto via `IdentityClientReadOnly`
3. **Fallback**: HTTP a Identity Service se blockchain lento/fallisce

```rust
impl DIDResolver {
    pub async fn resolve(&self, did: &str) -> IdentityResult<Arc<SimplifiedDIDDocument>> {
        // Cache first
        if let Some(cached) = self.cache.get(did).await {
            return Ok(cached);
        }

        // Blockchain
        match self.resolve_from_blockchain(did).await {
            Ok(doc) => {
                let simplified = self.convert_document(&doc);
                let arc = Arc::new(simplified);
                self.cache.insert(did.to_string(), Arc::clone(&arc)).await;
                return Ok(arc);
            }
            Err(_) => {}
        }

        // Fallback
        self.resolve_from_service(did).await
    }
}
```

---

### File: `device-client/src/storage/mod.rs`

**Scopo**: Storage sicuro file-based.

#### File Gestiti

| File | Contenuto | Permessi Unix |
|------|-----------|---------------|
| `identity.json` | DeviceIdentity | 0644 |
| `credential.json` | DeviceCredential | 0644 |
| `credential.jwt` | JWT raw | 0644 |
| `private_key.hex` | Chiave privata | **0600** |

```rust
impl SecureStorage {
    pub async fn store_private_key(&mut self, key_hex: &str) -> IdentityResult<()> {
        let path = self.storage_path.join("private_key.hex");
        tokio::fs::write(&path, key_hex).await?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path,
                std::fs::Permissions::from_mode(0o600))?;
        }

        self.private_key = Some(key_hex.to_string());
        Ok(())
    }
}
```

---

### File: `device-client/src/tls/mod.rs`

**Scopo**: TLS con autenticazione DID post-handshake.

#### Struct `TlsClient`

```rust
pub struct TlsClient {
    connector: TlsConnector,
    verifier: Arc<CredentialVerifier>,
    did: String,
    credential_jwt: String,
    signing_key: SigningKey,
    tls_config: TlsConfig,
}
```

#### Struct `TlsServer`

```rust
pub struct TlsServer {
    acceptor: TlsAcceptor,
    verifier: Arc<CredentialVerifier>,
    did: String,
    credential_jwt: String,
    signing_key: SigningKey,
    tls_config: TlsConfig,
}
```

#### Struct `AuthenticatedConnection`

```rust
pub struct AuthenticatedConnection {
    pub stream: TlsStream<TcpStream>,
    pub peer_did: String,
    pub peer_public_key: String,
    pub metrics: AuthenticationMetrics,
}
```

#### Configurazione TLS

```rust
impl TlsClient {
    pub fn new(...) -> Result<Self> {
        // Accetta qualsiasi certificato (l'identità è via DID)
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCertVerifier))
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));

        Ok(Self { connector, verifier, did, credential_jwt, signing_key, tls_config })
    }
}
```

**Nota Sicurezza**: I certificati TLS sono ignorati perché l'autenticazione avviene via DID/credenziali W3C VC. Questo sostituisce PKI tradizionale con identità decentralizzata.

#### Metodo `connect()`

```rust
impl TlsClient {
    pub async fn connect(&self, addr: &str) -> Result<AuthenticatedConnection> {
        let total_start = Instant::now();

        // 1. TCP Connect
        let stream = TcpStream::connect(addr).await?;

        // 2. TLS Handshake
        let tls_start = Instant::now();
        let mut tls_stream = self.connector.connect(
            ServerName::try_from("localhost")?,
            stream,
        ).await?;
        let tls_handshake_ms = tls_start.elapsed().as_millis() as u64;

        // 3. DID Authentication (post-handshake)
        let auth_start = Instant::now();
        let (peer_did, peer_public_key, credential_verify_ms, challenge_response_ms) =
            self.perform_did_auth(&mut tls_stream).await?;
        let did_auth_ms = auth_start.elapsed().as_millis() as u64;

        let metrics = AuthenticationMetrics {
            tls_handshake_ms,
            did_auth_ms,
            credential_verify_ms,
            challenge_response_ms,
            total_ms: total_start.elapsed().as_millis() as u64,
        };

        Ok(AuthenticatedConnection {
            stream: tls_stream,
            peer_did,
            peer_public_key,
            metrics,
        })
    }
}
```

#### Protocollo DID Auth (4 fasi)

```rust
impl TlsClient {
    async fn perform_did_auth(
        &self,
        stream: &mut TlsStream<TcpStream>,
    ) -> Result<(String, String, u64, u64)> {
        // === FASE 1: Hello ===
        // Client invia: DID + Credential JWT
        let hello = DIDAuthMessage {
            message_type: DIDAuthMessageType::Hello,
            did: Some(self.did.clone()),
            credential_jwt: Some(self.credential_jwt.clone()),
            ..Default::default()
        };
        send_message(stream, &hello).await?;

        // === FASE 2: Ricevi Challenge ===
        let challenge_msg: DIDAuthMessage = receive_message(stream).await?;
        if challenge_msg.message_type != DIDAuthMessageType::Challenge {
            return Err(anyhow!("Expected Challenge"));
        }
        let challenge = challenge_msg.challenge
            .ok_or_else(|| anyhow!("No challenge"))?;

        // === FASE 3: Response ===
        // Firma il challenge con chiave privata
        let signature = self.signing_key.sign(challenge.as_bytes());
        let response = DIDAuthMessage {
            message_type: DIDAuthMessageType::Response,
            signature: Some(hex::encode(signature.to_bytes())),
            public_key: Some(hex::encode(self.signing_key.verifying_key().as_bytes())),
            ..Default::default()
        };
        send_message(stream, &response).await?;

        // === FASE 4: Ricevi Verified ===
        let verified_msg: DIDAuthMessage = receive_message(stream).await?;
        if verified_msg.message_type == DIDAuthMessageType::Error {
            return Err(anyhow!("Auth failed: {:?}", verified_msg.error));
        }

        // Estrai info peer (dal server)
        let peer_did = verified_msg.did.unwrap_or_default();
        let peer_public_key = verified_msg.public_key.unwrap_or_default();

        Ok((peer_did, peer_public_key, 0, 0))
    }
}
```

#### Framing Messaggi

```rust
async fn send_message<T: Serialize>(
    stream: &mut TlsStream<TcpStream>,
    message: &T,
) -> Result<()> {
    let json = serde_json::to_vec(message)?;
    let len = json.len() as u32;

    // Length prefix (4 bytes big-endian)
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&json).await?;
    stream.flush().await?;

    Ok(())
}

async fn receive_message<T: DeserializeOwned>(
    stream: &mut TlsStream<TcpStream>,
) -> Result<T> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;

    Ok(serde_json::from_slice(&buf)?)
}
```

#### Struct `AcceptAnyCertVerifier`

```rust
struct AcceptAnyCertVerifier;

impl ServerCertVerifier for AcceptAnyCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Accetta qualsiasi certificato
        // L'autenticazione avviene via DID post-handshake
        Ok(ServerCertVerified::assertion())
    }
}
```

---

### File: `device-client/src/tls/verifier.rs`

**Scopo**: Verifica credenziali W3C VC e challenge-response.

#### Struct `CredentialVerifier`

```rust
pub struct CredentialVerifier {
    resolver: Arc<DIDResolver>,
    identity_service_url: String,
}
```

#### Struct `ParsedCredential`

```rust
struct ParsedCredential {
    header: JwtHeader,
    payload: JwtPayload,
    signature: Vec<u8>,
    signed_data: String,
}

struct JwtHeader {
    alg: String,
    typ: String,
    kid: Option<String>,
}

struct JwtPayload {
    vc: VcContent,
}

struct VcContent {
    id: String,
    issuer: String,
    credential_subject: CredentialSubject,
    credential_status: Option<CredentialStatus>,
    expiration_date: Option<String>,
}
```

#### Metodo `verify_credential()`

```rust
impl CredentialVerifier {
    pub async fn verify_credential(
        &self,
        jwt: &str,
    ) -> Result<(String, String)> {
        // 1. Parse JWT
        let parsed = self.parse_credential(jwt)?;

        // 2. Verifica algoritmo
        if parsed.header.alg != "EdDSA" {
            return Err(anyhow!("Unsupported algorithm: {}", parsed.header.alg));
        }

        // 3. Verifica scadenza
        if let Some(ref exp) = parsed.payload.vc.expiration_date {
            let exp_time = chrono::DateTime::parse_from_rfc3339(exp)?;
            if exp_time < chrono::Utc::now() {
                return Err(anyhow!("Credential expired"));
            }
        }

        // 4. Risolvi DID issuer e ottieni chiave pubblica
        let issuer_did = &parsed.payload.vc.issuer;
        let public_key = self.get_issuer_public_key(issuer_did).await?;

        // 5. Verifica firma
        self.verify_signature(&parsed.signed_data, &parsed.signature, &public_key)?;

        // 6. Verifica binding chiave pubblica
        let subject_did = &parsed.payload.vc.credential_subject.id;
        let subject_public_key = &parsed.payload.vc.credential_subject.public_key;
        self.verify_public_key_binding(subject_did, subject_public_key).await?;

        // 7. Check revoca (opzionale)
        if let Some(ref status) = parsed.payload.vc.credential_status {
            self.check_revocation_status(status).await?;
        }

        Ok((
            parsed.payload.vc.credential_subject.id.clone(),
            parsed.payload.vc.credential_subject.public_key.clone(),
        ))
    }
}
```

#### Metodo `get_issuer_public_key()`

```rust
impl CredentialVerifier {
    async fn get_issuer_public_key(&self, issuer_did: &str) -> Result<Vec<u8>> {
        let doc = self.resolver.resolve(issuer_did).await?;

        // Trova verification method
        let method = doc.verification_methods
            .first()
            .ok_or_else(|| anyhow!("No verification methods"))?;

        // Decodifica multibase (z = base58btc)
        self.decode_multibase_key(&method.public_key_multibase)
    }

    fn decode_multibase_key(&self, multibase: &str) -> Result<Vec<u8>> {
        if !multibase.starts_with('z') {
            return Err(anyhow!("Unsupported multibase prefix"));
        }

        let base58_str = &multibase[1..];
        bs58::decode(base58_str)
            .into_vec()
            .map_err(|e| anyhow!("Base58 decode failed: {}", e))
    }
}
```

#### Metodo `verify_signature()`

```rust
impl CredentialVerifier {
    fn verify_signature(
        &self,
        message: &str,
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<()> {
        let verifying_key = VerifyingKey::from_bytes(
            public_key.try_into()
                .map_err(|_| anyhow!("Invalid public key length"))?
        )?;

        let sig = Signature::from_slice(signature)?;

        verifying_key.verify(message.as_bytes(), &sig)
            .map_err(|e| anyhow!("Signature verification failed: {}", e))
    }
}
```

#### Metodo `check_revocation_status()`

```rust
impl CredentialVerifier {
    async fn check_revocation_status(&self, status: &CredentialStatus) -> Result<()> {
        if status.status_type != "RevocationBitmap2022" {
            return Ok(()); // Unknown type, skip
        }

        // Parse service URI per ottenere issuer DID
        let service_uri = &status.id;
        let issuer_did = service_uri
            .split('#')
            .next()
            .ok_or_else(|| anyhow!("Invalid status URI"))?;

        // Risolvi DID Document
        let doc = self.resolver.resolve(issuer_did).await?;

        // Trova servizio revocation
        let service = doc.service
            .as_ref()
            .and_then(|services| {
                services.iter().find(|s| s.service_type == "RevocationBitmap2022")
            })
            .ok_or_else(|| anyhow!("No revocation service found"))?;

        // Decodifica bitmap dall'endpoint
        let bitmap_data = self.extract_bitmap_data(&service.service_endpoint)?;
        let bitmap = OnChainRevocationManager::decode_service_endpoint(&bitmap_data)?;

        // Check indice
        if let Some(ref index_str) = status.revocation_bitmap_index {
            let index: u32 = index_str.parse()?;
            if bitmap.contains(index) {
                return Err(anyhow!("Credential has been revoked"));
            }
        }

        Ok(())
    }

    fn extract_bitmap_data(&self, endpoint: &str) -> Result<String> {
        // Format: data:application/octet-stream;base64,<data>
        endpoint
            .strip_prefix("data:application/octet-stream;base64,")
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Invalid bitmap endpoint format"))
    }
}
```

#### Metodo `verify_challenge_response()`

```rust
impl CredentialVerifier {
    pub fn verify_challenge_response(
        &self,
        challenge: &str,
        signature_hex: &str,
        public_key_hex: &str,
    ) -> Result<()> {
        let public_key = hex::decode(public_key_hex)?;
        let signature = hex::decode(signature_hex)?;

        let verifying_key = VerifyingKey::from_bytes(
            &public_key.try_into()
                .map_err(|_| anyhow!("Invalid key length"))?
        )?;

        let sig = Signature::from_slice(&signature)?;

        verifying_key.verify(challenge.as_bytes(), &sig)
            .map_err(|e| anyhow!("Challenge verification failed: {}", e))
    }
}
```

---

## Crate benchmarks/

Il crate `benchmarks` fornisce strumenti per misurare le performance del sistema.

### File: `benchmarks/src/main.rs`

**Scopo**: Suite di benchmark per operazioni critiche.

#### Benchmark Disponibili

| Benchmark | Descrizione | Metrica |
|-----------|-------------|---------|
| `did_creation` | Creazione DID on-chain | Latenza transazione |
| `did_resolution_cold` | Risoluzione DID (cache miss) | Latenza blockchain |
| `did_resolution_cached` | Risoluzione DID (cache hit) | Latenza cache |
| `credential_issuance` | Emissione credenziale JWT | Latenza firma |
| `credential_verification` | Verifica credenziale | Latenza verifica |

#### Statistiche HDR Histogram

Il benchmark usa HDR Histogram per catturare percentili accurati:

```rust
pub struct BenchmarkResult {
    pub name: String,
    pub iterations: usize,
    pub histogram: Histogram<u64>,
}

impl BenchmarkResult {
    pub fn mean_us(&self) -> f64 { self.histogram.mean() }
    pub fn p50_us(&self) -> u64 { self.histogram.value_at_percentile(50.0) }
    pub fn p95_us(&self) -> u64 { self.histogram.value_at_percentile(95.0) }
    pub fn p99_us(&self) -> u64 { self.histogram.value_at_percentile(99.0) }
}
```

---

## Tools Python

### `tools/accumulate_tokens.py`

Automazione richieste faucet IOTA testnet per accumulare token di test.

### `tools/derive_address.py`

Utility per derivare indirizzo IOTA da chiave privata Ed25519 usando Blake2b-256.

### `tools/test_registration.py`

Test di carico per registrazione dispositivi con concorrenza controllata e statistiche latenza.

---

## Flussi End-to-End

### Flusso Registrazione Dispositivo

1. **Device** genera coppia chiavi Ed25519
2. **Device** → POST `/api/v1/device/register` con `public_key`
3. **Identity Service** crea DID on-chain (transazione blockchain)
4. **Identity Service** alloca indice revoca (AtomicU32)
5. **Identity Service** emette credenziale JWT firmata
6. **Device** salva `identity.json`, `credential.jwt`, `private_key.hex`

### Flusso Connessione TLS + DID Auth

1. TCP Connect → TLS Handshake (certificati ignorati)
2. **Client** invia Hello: `{did, credential_jwt}`
3. **Server** verifica credenziale (firma, scadenza, revoca)
4. **Server** invia Challenge: 32 byte random
5. **Client** firma challenge con chiave privata
6. **Server** verifica firma corrisponda a public key in credenziale
7. Canale autenticato stabilito

### Flusso Revoca Credenziale

1. POST `/api/v1/revocation/revoke` con `credential_id`
2. Trova indice nel mapping `credential_to_index`
3. Imposta bit nel RoaringBitmap
4. Codifica bitmap (ZLIB + Base64)
5. Aggiorna DID Document con nuovo `serviceEndpoint`
6. Transazione blockchain per persistenza

---

## Gestione della Cache

### Cache a Due Livelli

- **DID Cache**: TTL 1 ora, max 10k entries
- **Credential Cache**: TTL 30 min, max 50k entries

### Pattern di Accesso

```rust
// Cache hit → return immediato (O(1))
if let Some(cached) = cache.get(did).await {
    return Ok(cached);
}

// Cache miss → resolve + cache
let doc = resolve_from_blockchain(did).await?;
cache.insert(did, Arc::new(doc)).await;
```

### Invalidazione

- Automatica dopo `rotate_key`
- Manuale via `/api/v1/admin/clear-caches`

---

## Propagazione degli Errori

### Categorie Errori (`IdentityError`)

- **DID**: InvalidDID, DIDNotFound, DIDCreationFailed
- **Credential**: CredentialExpired, CredentialRevoked, VerificationFailed
- **Crypto**: SignatureVerificationFailed, InvalidPublicKey
- **Network**: NetworkConnectionError, BlockchainError
- **TLS**: TlsHandshakeFailed, CertificateError
- **Storage**: StorageIOError, SerializationError

### Conversioni

```rust
// Automatiche via From trait
impl From<reqwest::Error> for IdentityError
impl From<std::io::Error> for IdentityError

// A HTTP via Axum IntoResponse
impl IntoResponse for ApiError
```

---

## Interazione con IOTA Blockchain

### SDK Components

| Componente | Uso |
|------------|-----|
| `IdentityClientReadOnly` | Query senza gas |
| `IdentityClient` | Operazioni con gas |
| `IotaDocument` | DID Document |
| `StorageSigner` | Firma transazioni |

### Gas Budget

```rust
const DID_CREATION_GAS: u64 = 100_000_000;  // 0.1 IOTA
const KEY_ROTATION_GAS: u64 = 75_000_000;   // 0.075 IOTA
const REVOCATION_GAS: u64 = 50_000_000;     // 0.05 IOTA
```

### DID Format

```
did:iota:testnet:0x<object_id_32_bytes_hex>
```

---

*Documento generato dall'analisi del codice sorgente.*
*Versione: 1.0 | Data: 2026-03-07*
