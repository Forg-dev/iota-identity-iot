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
# ✅ RevocationBitmap2022 (on-chain revocation)
#
# =============================================================================


# =============================================================================
# =============================================================================
#                    REVOCATIONBITMAP2022 - TEST ON-CHAIN
# =============================================================================
# =============================================================================
# Questi test verificano l'implementazione W3C RevocationBitmap2022 per la
# revoca on-chain delle credenziali. A differenza della revoca in-memory,
# questa è persistente e verificabile da qualsiasi parte terza.
# =============================================================================


# =============================================================================
# TEST 19: Statistiche Bitmap (stato iniziale)
# =============================================================================
# Verifica lo stato iniziale del bitmap di revoca.
# NOTA: I numeri dipendono da quanti test hai già eseguito.

curl -s "http://localhost:8080/api/v1/revocation/bitmap-stats" | jq .

# OUTPUT ATTESO:
# {
#   "issuer_did": "did:iota:testnet:issuer",
#   "total_credentials_issued": <numero>,
#   "revoked_count": <numero>,
#   "is_dirty": <true/false>,
#   "serialized_size_bytes": <numero>,
#   "revocation_type": "RevocationBitmap2022"
# }


# =============================================================================
# TEST 20: Registra Device e Verifica credentialStatus
# =============================================================================
# Le nuove credenziali includono credentialStatus con RevocationBitmap2022.

RESPONSE=$(curl -s -X POST "http://localhost:8080/api/v1/device/register" \
    -H "Content-Type: application/json" \
    -d '{
        "public_key": "'$(openssl rand -hex 32)'",
        "device_type": "sensor",
        "capabilities": ["temperature"]
    }')

echo "$RESPONSE" | jq .

# Salva i valori per i test successivi:
export BITMAP_DID=$(echo "$RESPONSE" | jq -r '.did')
export BITMAP_JWT=$(echo "$RESPONSE" | jq -r '.credential_jwt')

# Decodifica il JWT per vedere credentialStatus:
# (Nota: il credentialStatus è dentro .vc nel payload JWT)
echo "$BITMAP_JWT" | cut -d'.' -f2 | tr '_-' '/+' | awk '{while(length($0)%4)$0=$0"=";print}' | base64 -d | jq '.vc.credentialStatus'

# OUTPUT ATTESO:
# {
#   "id": "did:iota:testnet:issuer#revocation",
#   "type": "RevocationBitmap2022",
#   "revocationBitmapIndex": "<numero>"
# }

# Salva l'indice per i test successivi:
export REVOCATION_INDEX=$(echo "$BITMAP_JWT" | cut -d'.' -f2 | tr '_-' '/+' | awk '{while(length($0)%4)$0=$0"=";print}' | base64 -d | jq -r '.vc.credentialStatus.revocationBitmapIndex')
echo "Revocation Index: $REVOCATION_INDEX"


# =============================================================================
# TEST 21: Verifica Status On-Chain (NON revocato)
# =============================================================================
# Controlla che la credenziale appena creata NON sia revocata.

curl -s "http://localhost:8080/api/v1/credential/status-onchain/$REVOCATION_INDEX" | jq .

# OUTPUT ATTESO:
# {
#   "issuer_did": "did:iota:testnet:issuer",
#   "revocation_index": <numero>,
#   "revoked": false,
#   "checked_at": "2026-...",
#   "from_chain": false
# }


# =============================================================================
# TEST 22: Revoca On-Chain (RevocationBitmap2022)
# =============================================================================
# Revoca la credenziale usando RevocationBitmap2022.
# Questa revoca è persistente e verificabile da chiunque.

# Prima estrai l'ID della credenziale:
export BITMAP_CRED_ID=$(echo "$BITMAP_JWT" | cut -d'.' -f2 | tr '_-' '/+' | awk '{while(length($0)%4)$0=$0"=";print}' | base64 -d | jq -r '.vc.id')
echo "Credential ID: $BITMAP_CRED_ID"

# Esegui la revoca:
curl -s -X POST "http://localhost:8080/api/v1/credential/revoke-onchain" \
    -H "Content-Type: application/json" \
    -d "{
        \"credential_id\": \"$BITMAP_CRED_ID\",
        \"revocation_index\": $REVOCATION_INDEX,
        \"reason\": \"Device compromised - security breach\"
    }" | jq .

# OUTPUT ATTESO:
# {
#   "success": true,
#   "credential_id": "urn:uuid:...",
#   "revocation_index": <numero>,
#   "revoked_at": "2026-...",
#   "on_chain": true,
#   "transaction_id": null,
#   "error": null
# }


# =============================================================================
# TEST 23: Verifica Status On-Chain (ORA REVOCATO)
# =============================================================================
# La credenziale deve ora risultare revocata.

curl -s "http://localhost:8080/api/v1/credential/status-onchain/$REVOCATION_INDEX" | jq .

# OUTPUT ATTESO:
# {
#   "issuer_did": "did:iota:testnet:issuer",
#   "revocation_index": <numero>,
#   "revoked": true,    <-- CAMBIATO DA false A true!
#   "checked_at": "2026-...",
#   "from_chain": false
# }


# =============================================================================
# TEST 24: Tentativo Doppia Revoca (deve fallire)
# =============================================================================
# Non è possibile revocare due volte la stessa credenziale.

curl -s -X POST "http://localhost:8080/api/v1/credential/revoke-onchain" \
    -H "Content-Type: application/json" \
    -d "{
        \"credential_id\": \"$BITMAP_CRED_ID\",
        \"revocation_index\": $REVOCATION_INDEX,
        \"reason\": \"Second attempt\"
    }" | jq .

# OUTPUT ATTESO:
# {
#   "success": false,
#   "credential_id": "urn:uuid:...",
#   "revocation_index": <numero>,
#   "revoked_at": "2026-...",
#   "on_chain": false,
#   "error": "Credential at index <numero> (ID: urn:uuid:...) is already revoked"
# }


# =============================================================================
# TEST 25: Statistiche Bitmap (dopo revoca)
# =============================================================================
# Verifica che le statistiche riflettano la revoca.

curl -s "http://localhost:8080/api/v1/revocation/bitmap-stats" | jq .

# OUTPUT ATTESO:
# {
#   "issuer_did": "did:iota:testnet:issuer",
#   "total_credentials_issued": <precedente + 1>,
#   "revoked_count": <precedente + 1>,
#   "is_dirty": true,    <-- Il bitmap è stato modificato
#   "serialized_size_bytes": <numero>,
#   "revocation_type": "RevocationBitmap2022"
# }


# =============================================================================
# TEST 26: Registra Secondo Device (indice diverso)
# =============================================================================
# Verifica che il prossimo device ottenga un indice di revoca diverso.

RESPONSE2=$(curl -s -X POST "http://localhost:8080/api/v1/device/register" \
    -H "Content-Type: application/json" \
    -d '{
        "public_key": "'$(openssl rand -hex 32)'",
        "device_type": "gateway",
        "capabilities": ["routing"]
    }')

echo "$RESPONSE2" | jq .

# Verifica che l'indice sia incrementato:
echo "$RESPONSE2" | jq -r '.credential_jwt' | cut -d'.' -f2 | tr '_-' '/+' | awk '{while(length($0)%4)$0=$0"=";print}' | base64 -d | jq '.vc.credentialStatus'

# OUTPUT ATTESO:
# {
#   "id": "did:iota:testnet:issuer#revocation",
#   "type": "RevocationBitmap2022",
#   "revocationBitmapIndex": "<numero precedente + 1>"
# }


# =============================================================================
# TEST 27: Verifica Indice Non Revocato
# =============================================================================
# Il nuovo device non deve essere revocato.

NEW_INDEX=$(echo "$RESPONSE2" | jq -r '.credential_jwt' | cut -d'.' -f2 | tr '_-' '/+' | awk '{while(length($0)%4)$0=$0"=";print}' | base64 -d | jq -r '.vc.credentialStatus.revocationBitmapIndex')
echo "New Index: $NEW_INDEX"

curl -s "http://localhost:8080/api/v1/credential/status-onchain/$NEW_INDEX" | jq .

# OUTPUT ATTESO:
# {
#   "revocation_index": <nuovo indice>,
#   "revoked": false
# }


# =============================================================================
# VERIFICA SU IOTA EXPLORER
# =============================================================================
# Per ogni DID creato, puoi verificare lo stato on-chain:
# https://explorer.rebased.iota.org/object/<OBJECT_ID>?network=testnet
#
# L'object_id è la parte dopo "did:iota:testnet:" nel DID.
# Esempio: did:iota:testnet:0xabc123... -> object_id = 0xabc123...
# =============================================================================


# =============================================================================
# RIEPILOGO REVOCATIONBITMAP2022
# =============================================================================
#
# Il sistema implementa la specifica W3C RevocationBitmap2022:
#
# 1. STRUTTURA CREDENTIAL:
#    Ogni credenziale include un campo credentialStatus:
#    {
#      "id": "did:iota:testnet:issuer#revocation",
#      "type": "RevocationBitmap2022",
#      "revocationBitmapIndex": "N"
#    }
#
# 2. REVOCA:
#    - Ogni credenziale ha un indice univoco nel bitmap
#    - Revocare = impostare il bit a 1 all'indice specificato
#    - La revoca è irreversibile (nel nostro caso)
#
# 3. VERIFICA:
#    - Qualsiasi verifier può controllare lo stato
#    - Basta risolvere il DID dell'issuer e decodificare il bitmap
#    - Se il bit all'indice è 1, la credenziale è revocata
#
# 4. VANTAGGI vs REVOCA IN-MEMORY:
#    - Persistente (sopravvive ai restart)
#    - Verificabile pubblicamente
#    - Standard W3C
#    - Privacy-preserving (nessun tracking delle verifiche)
#
# =============================================================================