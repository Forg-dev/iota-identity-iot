# =============================================================================
# IOTA Identity IoT - Guida ai Test Manuali
# =============================================================================
# Esegui questi comandi uno alla volta e verifica l'output.
# Prerequisito: il servizio deve essere in esecuzione su localhost:8080
# =============================================================================

# =============================================================================
# TEST 1: Health Check
# =============================================================================
# Verifica che il servizio sia attivo.
# OUTPUT ATTESO: {"status":"healthy","version":"0.1.0"}

curl -s "http://localhost:8080/health" | jq .


# =============================================================================
# TEST 2: Registrazione Device
# =============================================================================
# Crea un nuovo device con DID on-chain. Richiede ~7-10 secondi.
# OUTPUT ATTESO: JSON con did, object_id, credential_jwt, credential_expires_at

curl -s -X POST "http://localhost:8080/api/v1/device/register" \
    -H "Content-Type: application/json" \
    -d '{
        "public_key": "'$(openssl rand -hex 32)'",
        "device_type": "sensor",
        "capabilities": ["temperature", "humidity"]
    }' | jq .

# SALVA IL DID per i test successivi! Esempio:
# export DID="did:iota:testnet:0x..."
# export CREDENTIAL_JWT="eyJ..."


# =============================================================================
# TEST 3: Risoluzione DID
# =============================================================================
# Recupera il DID Document dalla blockchain.
# NOTA: Sostituisci $DID con il DID ottenuto nel test 2
# OUTPUT ATTESO: JSON con did_document contenente id e verificationMethod

# Prima imposta il DID (copia quello del test 2):
export DID="did:iota:testnet:0x..."

# Poi risolvi:
DID_ENCODED=$(echo -n "$DID" | jq -sRr @uri)
curl -s "http://localhost:8080/api/v1/did/resolve/$DID_ENCODED" | jq .

# OUTPUT ATTESO:
# {
#   "did_document": {
#     "id": "did:iota:testnet:0x...",
#     "verificationMethod": [
#       {
#         "id": "did:iota:testnet:0x...#fragment",
#         "controller": "did:iota:testnet:0x...",
#         "type": "JsonWebKey2020",
#         "publicKeyMultibase": "z..."
#       }
#     ]
#   },
#   "from_cache": false,
#   "resolution_time_ms": 100
# }


# =============================================================================
# TEST 4: Risoluzione con Cache
# =============================================================================
# Esegui di nuovo la risoluzione - dovrebbe essere molto più veloce.
# OUTPUT ATTESO: from_cache: true, resolution_time_ms < 5

curl -s "http://localhost:8080/api/v1/did/resolve/$DID_ENCODED" | jq '{from_cache, resolution_time_ms}'

# OUTPUT ATTESO:
# {
#   "from_cache": true,
#   "resolution_time_ms": 0
# }


# =============================================================================
# TEST 5: Verifica Credential (Valida)
# =============================================================================
# Verifica che la credential JWT sia valida.
# NOTA: Sostituisci con il credential_jwt ottenuto nel test 2

export CREDENTIAL_JWT="eyJ..."

curl -s -X POST "http://localhost:8080/api/v1/credential/verify" \
    -H "Content-Type: application/json" \
    -d "{\"credential_jwt\": \"$CREDENTIAL_JWT\"}" | jq .

# OUTPUT ATTESO:
# {
#   "valid": true,
#   "subject_did": "did:iota:testnet:0x...",
#   "issuer_did": "did:iota:issuer",
#   "error": null,
#   "expires_at": "2027-..."
# }


# =============================================================================
# TEST 6: Verifica Credential (Invalida)
# =============================================================================
# Prova a verificare una credential malformata.
# OUTPUT ATTESO: valid: false, error: "Invalid JWT format"

curl -s -X POST "http://localhost:8080/api/v1/credential/verify" \
    -H "Content-Type: application/json" \
    -d '{"credential_jwt": "invalid.jwt.token"}' | jq .

# OUTPUT ATTESO:
# {
#   "valid": false,
#   "subject_did": null,
#   "issuer_did": null,
#   "error": "Invalid JWT format",
#   "expires_at": null
# }


# =============================================================================
# TEST 7: Revoca Credential (In-Memory)
# =============================================================================
# Revoca una credential. La revoca è in-memory (si perde al restart).
# Prima estrai l'ID della credential dal JWT:

# Decodifica il JWT per ottenere l'ID (seconda parte del JWT, base64):
echo "$CREDENTIAL_JWT" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq -r '.vc.id'

# Esempio output: urn:uuid:a18bc60b-7877-4b4b-93a7-5d0ef46abef1
export CREDENTIAL_ID="urn:uuid:..."

# Ora revoca:
curl -s -X POST "http://localhost:8080/api/v1/credential/revoke" \
    -H "Content-Type: application/json" \
    -d "{
        \"credential_id\": \"$CREDENTIAL_ID\",
        \"reason\": \"Device compromesso - test\"
    }" | jq .

# OUTPUT ATTESO:
# {
#   "success": true,
#   "credential_id": "urn:uuid:...",
#   "revoked_at": "2026-...",
#   "error": null
# }


# =============================================================================
# TEST 8: Status Credential (dopo revoca)
# =============================================================================
# Verifica lo stato della credential revocata.

CRED_ID_ENCODED=$(echo -n "$CREDENTIAL_ID" | jq -sRr @uri)
curl -s "http://localhost:8080/api/v1/credential/status/$CRED_ID_ENCODED" | jq .

# OUTPUT ATTESO:
# {
#   "credential_id": "urn:uuid:...",
#   "revoked": true,
#   "revoked_at": "2026-...",
#   "reason": "Device compromesso - test"
# }


# =============================================================================
# TEST 9: Verifica Credential Revocata
# =============================================================================
# La verifica deve fallire per una credential revocata.

curl -s -X POST "http://localhost:8080/api/v1/credential/verify" \
    -H "Content-Type: application/json" \
    -d "{\"credential_jwt\": \"$CREDENTIAL_JWT\"}" | jq .

# OUTPUT ATTESO:
# {
#   "valid": false,
#   "subject_did": "did:iota:testnet:0x...",
#   "issuer_did": "did:iota:issuer",
#   "error": "Credential revoked at ... - Reason: Device compromesso - test",
#   "expires_at": "2027-..."
# }


# =============================================================================
# TEST 10: Key Rotation (On-Chain)
# =============================================================================
# Ruota la chiave del DID. Questa operazione è ON-CHAIN (~7 secondi).
# IMPORTANTE: Usa un DID che hai creato tu (hai il controllo).

# Conta le verification methods PRIMA della rotazione:
curl -s "http://localhost:8080/api/v1/did/resolve/$DID_ENCODED" | jq '.did_document.verificationMethod | length'
# OUTPUT ATTESO: 1

# Esegui la rotazione:
curl -s -X POST "http://localhost:8080/api/v1/did/rotate-key/$DID_ENCODED" \
    -H "Content-Type: application/json" \
    -d "{\"new_public_key\": \"$(openssl rand -hex 32)\"}" | jq .

# OUTPUT ATTESO:
# {
#   "success": true,
#   "did": "did:iota:testnet:0x...",
#   "new_verification_method_id": "abc123...",
#   "rotated_at": "2026-...",
#   "error": null
# }

# Pulisci la cache per vedere l'aggiornamento:
curl -s -X POST "http://localhost:8080/api/v1/admin/cache/clear" | jq .

# Verifica che ora ci sono 2 verification methods:
curl -s "http://localhost:8080/api/v1/did/resolve/$DID_ENCODED" | jq '.did_document.verificationMethod | length'
# OUTPUT ATTESO: 2

# Verifica su IOTA Explorer (sostituisci con il tuo object_id):
# https://explorer.rebased.iota.org/object/0x...?network=testnet


# =============================================================================
# TEST 11: Registra Secondo Device (per test deactivation)
# =============================================================================
# Crea un nuovo device che poi disattiveremo.

curl -s -X POST "http://localhost:8080/api/v1/device/register" \
    -H "Content-Type: application/json" \
    -d '{
        "public_key": "'$(openssl rand -hex 32)'",
        "device_type": "actuator",
        "capabilities": ["relay"]
    }' | jq .

# SALVA questo DID per il test di deactivation:
export DID2="did:iota:testnet:0x..."
export DID2_ENCODED=$(echo -n "$DID2" | jq -sRr @uri)


# =============================================================================
# TEST 12: DID Deactivation (On-Chain)
# =============================================================================
# Disattiva permanentemente un DID sulla blockchain.
# ATTENZIONE: Questa operazione è IRREVERSIBILE!

curl -s -X POST "http://localhost:8080/api/v1/did/deactivate/$DID2_ENCODED" | jq .

# OUTPUT ATTESO:
# {
#   "success": true,
#   "did": "did:iota:testnet:0x...",
#   "deactivated_at": "2026-...",
#   "transaction_id": null,
#   "error": null
# }


# =============================================================================
# TEST 13: Doppia Deactivation (deve fallire)
# =============================================================================
# Provare a disattivare di nuovo lo stesso DID deve fallire.

curl -s -X POST "http://localhost:8080/api/v1/did/deactivate/$DID2_ENCODED" | jq .

# OUTPUT ATTESO:
# {
#   "success": false,
#   "did": "did:iota:testnet:0x...",
#   "deactivated_at": "...",
#   "transaction_id": null,
#   "error": "DID already deactivated: did:iota:testnet:0x..."
# }


# =============================================================================
# TEST 14: Key Rotation su DID Deactivated (deve fallire)
# =============================================================================
# Non si può ruotare la chiave di un DID disattivato.

curl -s -X POST "http://localhost:8080/api/v1/did/rotate-key/$DID2_ENCODED" \
    -H "Content-Type: application/json" \
    -d "{\"new_public_key\": \"$(openssl rand -hex 32)\"}" | jq .

# OUTPUT ATTESO:
# {
#   "success": false,
#   "did": "did:iota:testnet:0x...",
#   "new_verification_method_id": null,
#   "rotated_at": "...",
#   "error": "DID already deactivated: did:iota:testnet:0x..."
# }


# =============================================================================
# TEST 15: Operazioni su DID Esterno (deve fallire)
# =============================================================================
# Non possiamo modificare DID che non abbiamo creato noi.

FAKE_DID="did:iota:testnet:0x0000000000000000000000000000000000000000000000000000000000000000"
FAKE_DID_ENCODED=$(echo -n "$FAKE_DID" | jq -sRr @uri)

# Tentativo di deactivation:
curl -s -X POST "http://localhost:8080/api/v1/did/deactivate/$FAKE_DID_ENCODED" | jq .

# OUTPUT ATTESO:
# {
#   "success": false,
#   "error": "Cannot deactivate: DID was not created by this service"
# }

# Tentativo di key rotation:
curl -s -X POST "http://localhost:8080/api/v1/did/rotate-key/$FAKE_DID_ENCODED" \
    -H "Content-Type: application/json" \
    -d "{\"new_public_key\": \"$(openssl rand -hex 32)\"}" | jq .

# OUTPUT ATTESO:
# {
#   "success": false,
#   "error": "Cannot rotate key: DID was not created by this service"
# }


# =============================================================================
# TEST 16: Validazione Input
# =============================================================================

# 16a. Public key troppo corta:
curl -s -X POST "http://localhost:8080/api/v1/device/register" \
    -H "Content-Type: application/json" \
    -d '{
        "public_key": "tooshort",
        "device_type": "sensor",
        "capabilities": []
    }' | jq .

# OUTPUT ATTESO:
# {
#   "error": "Public key must be 64 hex characters (32 bytes)"
# }

# 16b. Device type invalido:
curl -s -X POST "http://localhost:8080/api/v1/device/register" \
    -H "Content-Type: application/json" \
    -d '{
        "public_key": "'$(openssl rand -hex 32)'",
        "device_type": "InvalidType",
        "capabilities": []
    }' | jq .

# OUTPUT ATTESO: Errore di deserializzazione


# =============================================================================
# TEST 17: Metriche
# =============================================================================
# Visualizza le metriche del sistema.

curl -s "http://localhost:8080/metrics" | jq .

# OUTPUT ATTESO:
# {
#   "cache": {
#     "did_documents": <numero>,
#     "credentials": <numero>,
#     "enabled": true
#   },
#   "network": "testnet",
#   "endpoint": "https://api.testnet.iota.cafe"
# }


# =============================================================================
# TEST 18: Clear Cache
# =============================================================================
# Pulisce tutte le cache.

curl -s -X POST "http://localhost:8080/api/v1/admin/cache/clear" | jq .

# OUTPUT ATTESO:
# {
#   "status": "ok",
#   "message": "All caches cleared"
# }


# =============================================================================
# RIEPILOGO FEATURE TESTATE
# =============================================================================
#
# ✅ Health Check
# ✅ Device Registration (on-chain DID creation)
# ✅ DID Resolution (with caching)
# ✅ Credential Issuance (JWT)
# ✅ Credential Verification (valid/invalid)
# ✅ Credential Revocation (in-memory)
# ✅ Credential Status Check
# ✅ Key Rotation (on-chain)
# ✅ DID Deactivation (on-chain, irreversible)
# ✅ Authorization Checks (no control = no modify)
# ✅ Input Validation
# ✅ Metrics
# ✅ Cache Management
#
# =============================================================================
# VERIFICA SU IOTA EXPLORER
# =============================================================================
# Per ogni DID creato, puoi verificare lo stato on-chain:
# https://explorer.rebased.iota.org/object/<OBJECT_ID>?network=testnet
#
# L'object_id è la parte dopo "did:iota:testnet:" nel DID.
# Esempio: did:iota:testnet:0xabc123... -> object_id = 0xabc123...
# =============================================================================