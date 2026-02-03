# IOTA Identity IoT - Guida Completa ai Test Manuali

Questa guida accompagna attraverso i test manuali del sistema di identita decentralizzata per IoT. Ogni test include una spiegazione dettagliata di **cosa** viene testato, **perchè** è importante e **cosa aspettarsi** come risultato.

---

## Indice

- [Prerequisiti](#prerequisiti)
- [Sezione A: Test Base del Servizio](#sezione-a-test-base-del-servizio)
- [Sezione B: Ciclo di Vita DID](#sezione-b-ciclo-di-vita-did)
- [Sezione C: Verifiable Credentials](#sezione-c-verifiable-credentials)
- [Sezione D: RevocationBitmap2022 (On-Chain)](#sezione-d-revocationbitmap2022-on-chain) *(richiede Sezione E)*
- [Sezione E: Inizializzazione Issuer On-Chain](#sezione-e-inizializzazione-issuer-on-chain) *(eseguire prima di D per revoca on-chain)*
- [Sezione F: Device Client CLI](#sezione-f-device-client-cli)
- [Sezione G: Test di Persistenza](#sezione-g-test-di-persistenza)
- [Sezione H: Validazione Input](#sezione-h-validazione-input)
- [Sezione I: TLS con Autenticazione DID](#sezione-i-tls-con-autenticazione-did)
- [Riepilogo Architettura](#riepilogo-architettura)

> **Ordine consigliato per test completi:** A -> E -> B -> C -> D -> F -> G -> H -> I

---

## Prerequisiti

### 1. Compila il progetto

```bash
cd ~/iota-identity-iot
cargo build --release
```

### 2. Avvia l'Identity Service

```bash
# Terminale 1: Aggiungi le variabili di sistema e avvia il servizio
export IOTA_IDENTITY_PKG_ID=0x222741bbdff74b42df48a7b4733185e9b24becb8ccfbafe8eac864ab4e4cc555
export IOTA_NETWORK=testnet
cargo run --release --package identity-service
```

Attendi il messaggio: `Server running at http://0.0.0.0:8080`

### 3. Verifica i prerequisiti

```bash
# Verifica che curl e jq siano installati
curl --version
jq --version

# Verifica che openssl sia disponibile (per generare chiavi casuali)
openssl version
```

---

## Sezione A: Test Base del Servizio

Questi test verificano che il servizio sia operativo e risponda correttamente.

---

### TEST A1: Health Check

**Cosa testiamo:** L'endpoint `/health` che indica se il servizio e attivo e funzionante.

**Perchè è importante:** E il primo controllo da fare per verificare che il servizio sia partito correttamente. Viene usato anche dai load balancer e sistemi di monitoring per verificare lo stato del servizio.

**Comando:**
```bash
curl -s "http://localhost:8080/health" | jq .
```

**Output atteso:**
```json
{
  "status": "healthy",
  "version": "0.1.0"
}
```

**Se fallisce:** Il servizio non e in esecuzione o c'e un errore di configurazione.

---

### TEST A2: Metriche del Sistema

**Cosa testiamo:** L'endpoint `/metrics` che espone le metriche interne del sistema.

**Perchè è importante:** Permette di monitorare lo stato delle cache, la rete utilizzata e altre informazioni operative. Utile per debugging e monitoring in produzione.

**Comando:**
```bash
curl -s "http://localhost:8080/metrics" | jq .
```

**Output atteso:**
```json
{
  "cache": {
    "did_documents": 0,
    "credentials": 0,
    "enabled": true
  },
  "network": "testnet",
  "endpoint": "https://api.testnet.iota.cafe"
}
```

**Note:** I numeri delle cache aumenteranno man mano che usi il sistema.

---

## Sezione E: Inizializzazione Issuer On-Chain

Questi test verificano l'inizializzazione dell'issuer DID con il servizio RevocationBitmap2022.

> **IMPORTANTE:** Esegui questa sezione PRIMA delle altre se vuoi che le credenziali siano verificabili e le revoche funzionino on-chain. L'inizializzazione crea un DID on-chain con la chiave pubblica dell'issuer usata per firmare le credenziali.

---

### TEST E1: Status Issuer (Prima dell'inizializzazione)

**Cosa testiamo:** Lo stato dell'issuer DID prima dell'inizializzazione.

**Perchè è importante:** L'issuer deve avere un DID on-chain con il servizio RevocationBitmap2022 configurato per poter revocare credenziali in modo permanente.

**Comando:**
```bash
curl -s "http://localhost:8080/api/v1/issuer/status" | jq .
```

**Output atteso (se NON inizializzato):**
```json
{
  "initialized": false,
  "issuer_did": "did:iota:testnet:issuer",
  "on_chain_did": null,
  "has_control": false,
  "initialized_on_chain": false,
  "message": "Call POST /api/v1/issuer/initialize to create issuer DID on-chain."
}
```

**Output atteso (se gia inizializzato da sessione precedente):**
```json
{
  "initialized": true,
  "issuer_did": "did:iota:testnet:0x...",
  "on_chain_did": "did:iota:testnet:0x...",
  "has_control": true,
  "initialized_on_chain": true,
  "revocation_service_id": "did:iota:testnet:0x...#revocation",
  "message": "Issuer is fully initialized with on-chain DID and RevocationBitmap2022"
}
```

**Nota su `has_control`:** Questo campo indica se il servizio puo modificare il DID (aggiungere servizi, revocare credenziali on-chain). Dopo un riavvio, se la persistenza funziona correttamente, `has_control` deve essere `true`.

---

### TEST E2: Inizializzazione Issuer On-Chain

**Cosa testiamo:** L'inizializzazione del DID dell'issuer con il servizio di revoca.

**Perchè è importante:** Prima di poter revocare credenziali on-chain, l'issuer deve avere:
1. Un DID sulla blockchain contenente la sua chiave pubblica di firma
2. Un servizio RevocationBitmap2022 nel DID Document

Questa operazione:
- Crea un nuovo DID on-chain usando la chiave del CredentialIssuer
- Aggiunge il servizio RevocationBitmap2022
- Salva l'identita dell'issuer su disco (`~/.iota-identity-service/`) per la persistenza
- Salva anche la chiave di transazione (`tx_key_hex`) per mantenere il controllo del DID dopo i riavvii

**NOTA:** Esegui questo test SOLO se E1 ha mostrato `initialized: false`.

**Comando:**
```bash
curl -s -X POST "http://localhost:8080/api/v1/issuer/initialize" | jq .
```

**Output atteso:**
```json
{
  "success": true,
  "issuer_did": "did:iota:testnet:0x...",
  "revocation_service_id": "did:iota:testnet:0x...#revocation",
  "on_chain": true,
  "message": "Issuer DID created with RevocationBitmap2022 service"
}
```

**Tempo atteso:** 15-30 secondi (creazione DID + aggiunta servizio revoca on-chain)

---

### TEST E3: Verifica Persistenza Issuer su Disco

**Cosa testiamo:** Che l'identita dell'issuer sia stata salvata su disco con tutti i campi necessari.

**Perchè è importante:** L'identita dell'issuer viene salvata in `~/.iota-identity-service/issuer_identity.json`. Questo permette al servizio di mantenere la stessa identita E il controllo del DID dopo un riavvio, garantendo che le credenziali emesse rimangano verificabili e che le revoche on-chain continuino a funzionare.

**Comando:**
```bash
# Verifica che la directory esista
ls -la ~/.iota-identity-service/

# Visualizza il contenuto del file (contiene chiavi private, non condividere!)
cat ~/.iota-identity-service/issuer_identity.json | jq .
```

**Output atteso:**
```
total 12
drwxr-xr-x  2 user user 4096 Feb  3 02:33 .
drwxr-x--- 21 user user 4096 Feb  3 02:45 ..
-rw-r--r--  1 user user  350 Feb  3 02:33 issuer_identity.json

{
  "did": "did:iota:testnet:0x...",
  "signing_key_hex": "...",
  "tx_key_hex": "...",
  "verification_method_fragment": "issuer-key-1",
  "created_at": "2026-02-03T..."
}
```

**Campi importanti:**
- `signing_key_hex`: Chiave per firmare le credenziali
- `tx_key_hex`: Chiave per le transazioni blockchain (modifiche al DID) - **essenziale per la persistenza del controllo**
- `verification_method_fragment`: ID del metodo di verifica nel DID Document

---

### TEST E4: Status Issuer (Dopo l'inizializzazione)

**Cosa testiamo:** Verifica che l'issuer sia correttamente inizializzato con controllo completo.

**Comando:**
```bash
curl -s "http://localhost:8080/api/v1/issuer/status" | jq .
```

**Output atteso:**
```json
{
  "initialized": true,
  "issuer_did": "did:iota:testnet:0x...",
  "on_chain_did": "did:iota:testnet:0x...",
  "has_control": true,
  "initialized_on_chain": true,
  "revocation_service_id": "did:iota:testnet:0x...#revocation",
  "message": "Issuer is fully initialized with on-chain DID and RevocationBitmap2022"
}
```

**Verifica critica:** `has_control: true` indica che il servizio puo modificare il DID (necessario per le revoche on-chain).

---

## Sezione B: Ciclo di Vita DID

Questi test coprono l'intero ciclo di vita di un Decentralized Identifier (DID): creazione, risoluzione, rotazione chiavi e disattivazione.

---

### TEST B1: Registrazione Device (Creazione DID On-Chain)

**Cosa testiamo:** La creazione di un nuovo DID sulla blockchain IOTA Rebased tramite registrazione di un device IoT.

**Perchè è importante:** Questo e il cuore del sistema. Quando un device si registra:
1. Viene creato un DID Document sulla blockchain (~7-15 secondi)
2. Il device riceve un DID univoco e permanente
3. Viene emessa una Verifiable Credential (JWT) che attesta l'identita del device

**Comando:**
```bash
RESPONSE=$(curl -s -X POST "http://localhost:8080/api/v1/device/register" \
    -H "Content-Type: application/json" \
    -d '{
        "public_key": "'$(openssl rand -hex 32)'",
        "device_type": "sensor",
        "capabilities": ["temperature", "humidity"]
    }')

echo "$RESPONSE" | jq .

# IMPORTANTE: Salva questi valori per i test successivi!
export DID=$(echo "$RESPONSE" | jq -r '.did')
export OBJECT_ID=$(echo "$RESPONSE" | jq -r '.object_id')
export CREDENTIAL_JWT=$(echo "$RESPONSE" | jq -r '.credential_jwt')

echo "DID salvato: $DID"
```

**Output atteso:**
```json
{
  "did": "did:iota:testnet:0x...",
  "object_id": "0x...",
  "credential_jwt": "eyJhbGciOiJFZERTQSJ9...",
  "credential_expires_at": "2027-02-02T..."
}
```

**Tempo atteso:** 7-15 secondi (include transazione blockchain)

**Verifica on-chain:** Puoi verificare il DID su IOTA Explorer:
```
https://explorer.rebased.iota.org/object/<OBJECT_ID>?network=testnet
```

---

### TEST B2: Risoluzione DID (Prima volta - da blockchain)

**Cosa testiamo:** Il recupero del DID Document dalla blockchain IOTA.

**Perchè è importante:** La risoluzione DID e fondamentale per la verifica delle credenziali. Quando un verifier riceve una credenziale, deve risolvere il DID dell'issuer per ottenere la chiave pubblica e verificare la firma. La prima risoluzione richiede una query alla blockchain.

**Comando:**
```bash
# Codifica il DID per l'URL
DID_ENCODED=$(echo -n "$DID" | jq -sRr @uri)

curl -s "http://localhost:8080/api/v1/did/resolve/$DID_ENCODED" | jq .
```

**Output atteso:**
```json
{
  "did_document": {
    "id": "did:iota:testnet:0x...",
    "verificationMethod": [
      {
        "id": "did:iota:testnet:0x...#key-1",
        "controller": "did:iota:testnet:0x...",
        "type": "JsonWebKey2020",
        "publicKeyMultibase": "z..."
      }
    ]
  },
  "from_cache": false,
  "resolution_time_ms": 150
}
```

**Note:** `from_cache: false` indica che il documento e stato recuperato dalla blockchain.

---

### TEST B3: Risoluzione DID (Seconda volta - da cache)

**Cosa testiamo:** Il sistema di caching per la risoluzione DID.

**Perchè è importante:** Ogni query alla blockchain richiede tempo (~100-200ms). Il caching permette risoluzioni successive quasi istantanee (<1ms), fondamentale per verificare molte credenziali rapidamente. Questo e uno dei vantaggi chiave rispetto a OCSP nel PKI tradizionale.

**Comando:**
```bash
curl -s "http://localhost:8080/api/v1/did/resolve/$DID_ENCODED" | jq '{from_cache, resolution_time_ms}'
```

**Output atteso:**
```json
{
  "from_cache": true,
  "resolution_time_ms": 0
}
```

**Confronto performance:**
| Metodo | Tempo |
|--------|-------|
| Blockchain (cold) | 100-200ms |
| Cache (warm) | <1ms |
| OCSP tradizionale | 50-200ms (ogni volta) |

---

### TEST B4: Key Rotation (Rotazione Chiave On-Chain)

**Cosa testiamo:** L'aggiunta di una nuova chiave di verifica al DID Document.

**Perchè è importante:** La rotazione delle chiavi e essenziale per la sicurezza:
- Se una chiave privata viene compromessa, si puo aggiungere una nuova chiave
- Le vecchie credenziali rimangono valide (verificabili con la vecchia chiave)
- Le nuove credenziali useranno la nuova chiave

Questa operazione modifica il DID Document on-chain (~7-15 secondi).

**Comando:**
```bash
# Prima: conta le verification methods
echo "Verification methods PRIMA:"
curl -s "http://localhost:8080/api/v1/did/resolve/$DID_ENCODED" | jq '.did_document.verificationMethod | length'

# Esegui la rotazione
curl -s -X POST "http://localhost:8080/api/v1/did/rotate-key/$DID_ENCODED" \
    -H "Content-Type: application/json" \
    -d "{\"new_public_key\": \"$(openssl rand -hex 32)\"}" | jq .

# Pulisci la cache per vedere l'aggiornamento
curl -s -X POST "http://localhost:8080/api/v1/admin/cache/clear" > /dev/null

# Dopo: verifica che ci sia una chiave in piu
echo "Verification methods DOPO:"
curl -s "http://localhost:8080/api/v1/did/resolve/$DID_ENCODED" | jq '.did_document.verificationMethod | length'
```

**Output atteso:**
```
Verification methods PRIMA:
1
{
  "success": true,
  "did": "did:iota:testnet:0x...",
  "new_verification_method_id": "...",
  "rotated_at": "2026-...",
  "error": null
}
Verification methods DOPO:
2
```

**Tempo atteso:** ~7-15 secondi (transazione blockchain)

---

### TEST B5: Registra Secondo Device (per test deactivation)

**Cosa testiamo:** Creiamo un secondo device che poi disattiveremo.

**Perchè è importante:** Serve per testare la disattivazione senza perdere il DID principale che usiamo per gli altri test.

**Comando:**
```bash
RESPONSE2=$(curl -s -X POST "http://localhost:8080/api/v1/device/register" \
    -H "Content-Type: application/json" \
    -d '{
        "public_key": "'$(openssl rand -hex 32)'",
        "device_type": "actuator",
        "capabilities": ["relay", "switch"]
    }')

echo "$RESPONSE2" | jq .

export DID2=$(echo "$RESPONSE2" | jq -r '.did')
export DID2_ENCODED=$(echo -n "$DID2" | jq -sRr @uri)
echo "DID2 salvato: $DID2"
```

---

### TEST B6: DID Deactivation (Disattivazione Permanente)

**Cosa testiamo:** La disattivazione permanente di un DID sulla blockchain.

**Perchè è importante:** Quando un device viene dismesso o compromesso irreparabilmente, il suo DID deve essere disattivato. Questo:
- Impedisce qualsiasi operazione futura con quel DID
- Segnala a tutti i verifier che il DID non e piu valido
- E un'operazione **IRREVERSIBILE** (come la revoca di un certificato root)

**ATTENZIONE: Questa operazione NON puo essere annullata!**

**Comando:**
```bash
curl -s -X POST "http://localhost:8080/api/v1/did/deactivate/$DID2_ENCODED" | jq .
```

**Output atteso:**
```json
{
  "success": true,
  "did": "did:iota:testnet:0x...",
  "deactivated_at": "2026-...",
  "message": "DID deactivated on-chain"
}
```

---

### TEST B7: Operazioni su DID Disattivato (devono fallire)

**Cosa testiamo:** Che non sia possibile effettuare operazioni su un DID disattivato.

**Perchè è importante:** Un DID disattivato deve rimanere "morto". Nessuna operazione deve essere permessa per prevenire abusi.

**Comando:**
```bash
# Tentativo di doppia disattivazione
echo "Test doppia disattivazione:"
curl -s -X POST "http://localhost:8080/api/v1/did/deactivate/$DID2_ENCODED" | jq .

# Tentativo di key rotation su DID disattivato
echo "Test key rotation su DID disattivato:"
curl -s -X POST "http://localhost:8080/api/v1/did/rotate-key/$DID2_ENCODED" \
    -H "Content-Type: application/json" \
    -d "{\"new_public_key\": \"$(openssl rand -hex 32)\"}" | jq .
```

**Output atteso:**
```json
{
  "success": false,
  "error": "DID already deactivated: did:iota:testnet:0x..."
}
```

---

### TEST B8: Operazioni su DID Non Controllato (devono fallire)

**Cosa testiamo:** Che non sia possibile modificare DID creati da altri.

**Perchè è importante:** Solo chi ha creato un DID (e possiede le chiavi) puo modificarlo. Questo test verifica che il sistema impedisca operazioni non autorizzate.

**Comando:**
```bash
# DID fittizio (non creato da noi)
FAKE_DID="did:iota:testnet:0x0000000000000000000000000000000000000000000000000000000000000000"
FAKE_DID_ENCODED=$(echo -n "$FAKE_DID" | jq -sRr @uri)

echo "Test deactivation su DID non controllato:"
curl -s -X POST "http://localhost:8080/api/v1/did/deactivate/$FAKE_DID_ENCODED" | jq .

echo "Test key rotation su DID non controllato:"
curl -s -X POST "http://localhost:8080/api/v1/did/rotate-key/$FAKE_DID_ENCODED" \
    -H "Content-Type: application/json" \
    -d "{\"new_public_key\": \"$(openssl rand -hex 32)\"}" | jq .
```

**Output atteso:**
```json
{
  "success": false,
  "error": "Unauthorized operation: No control info for DID... Cannot update DIDs not created by this service."
}
```

---

## Sezione C: Verifiable Credentials

Questi test verificano l'emissione e la verifica delle Verifiable Credentials (VC) in formato JWT.

---

### TEST C1: Verifica Credential Valida

**Cosa testiamo:** La verifica di una credential JWT valida.

**Perchè è importante:** La verifica delle credenziali e il modo in cui un verifier (es. un gateway, un altro device, un server) puo accertarsi dell'identita di un device. Il processo include:
1. Decodifica del JWT
2. Risoluzione del DID dell'issuer
3. Verifica della firma Ed25519
4. Controllo della scadenza
5. Controllo dello stato di revoca

**Comando:**
```bash
curl -s -X POST "http://localhost:8080/api/v1/credential/verify" \
    -H "Content-Type: application/json" \
    -d "{\"credential_jwt\": \"$CREDENTIAL_JWT\"}" | jq .
```

**Output atteso:**
```json
{
  "valid": true,
  "issuer": "did:iota:testnet:0x...",
  "subject": "did:iota:testnet:0x...",
  "issuance_date": "2026-02-03T...",
  "expiration_date": "2027-02-03T...",
  "revocation_status": {
    "revoked": false,
    "index": 1
  },
  "verification_time_ms": 0
}
```

---

### TEST C2: Verifica Credential Malformata

**Cosa testiamo:** Che il sistema rifiuti correttamente credenziali malformate.

**Perchè è importante:** Il sistema deve gestire gracefully input invalidi e fornire messaggi di errore chiari. Questo previene attacchi con payload malformati.

**Comando:**
```bash
# JWT completamente invalido
echo "Test JWT invalido:"
curl -s -X POST "http://localhost:8080/api/v1/credential/verify" \
    -H "Content-Type: application/json" \
    -d '{"credential_jwt": "questo.non.e.un.jwt.valido"}' | jq .

# JWT con struttura corretta ma firma invalida
echo "Test JWT con firma invalida:"
curl -s -X POST "http://localhost:8080/api/v1/credential/verify" \
    -H "Content-Type: application/json" \
    -d '{"credential_jwt": "eyJhbGciOiJFZERTQSJ9.eyJ0ZXN0IjoidGVzdCJ9.invalidsignature"}' | jq .
```

**Output atteso:**
```json
{
  "valid": false,
  "error": "Invalid JWT format..."
}
```

---

### TEST C3: Decodifica Contenuto Credential

**Cosa testiamo:** Esaminiamo il contenuto del JWT per capirne la struttura.

**Perchè è importante:** Capire la struttura della credenziale aiuta a comprendere:
- Quali claim sono inclusi
- Come funziona il credentialStatus per la revoca
- La struttura W3C Verifiable Credentials

**Comando:**
```bash
# Decodifica il payload JWT (seconda parte, base64url)
echo "Contenuto della credential:"
echo "$CREDENTIAL_JWT" | cut -d'.' -f2 | tr '_-' '/+' | \
    awk '{while(length($0)%4)$0=$0"=";print}' | base64 -d | jq .
```

**Output atteso:**
```json
{
  "vc": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiableCredential", "IoTDeviceCredential"],
    "credentialSubject": {
      "id": "did:iota:testnet:0x...",
      "deviceType": "sensor",
      "capabilities": ["temperature", "humidity"]
    },
    "credentialStatus": {
      "id": "did:iota:testnet:...#revocation",
      "type": "RevocationBitmap2022",
      "revocationBitmapIndex": "1"
    },
    "issuer": "did:iota:testnet:...",
    "issuanceDate": "2026-...",
    "expirationDate": "2027-..."
  },
  "iss": "did:iota:testnet:...",
  "sub": "did:iota:testnet:..."
}
```

**Note sul credentialStatus:**
- `type`: "RevocationBitmap2022" indica il metodo di revoca usato
- `revocationBitmapIndex`: l'indice nel bitmap che corrisponde a questa credenziale

---

## Sezione D: RevocationBitmap2022 (On-Chain)

Questi test verificano l'implementazione W3C RevocationBitmap2022 per la revoca persistente delle credenziali.

> **IMPORTANTE: Prerequisito**
> 
> Per eseguire la revoca **on-chain** (con `on_chain: true`), devi prima inizializzare l'Issuer DID.
> Se non lo hai ancora fatto, esegui **prima la Sezione E** (TEST E1 e E2).
> 
> Senza l'inizializzazione dell'issuer, la revoca non funzionera.

### Cos'e RevocationBitmap2022?

E uno standard W3C per la revoca efficiente delle credenziali:
- Ogni credenziale ha un indice univoco nel bitmap
- Il bitmap e un array di bit dove 0=valido, 1=revocato
- Compresso con Roaring Bitmap + ZLIB per efficienza
- Memorizzato nel DID Document dell'issuer

**Vantaggi rispetto a CRL/OCSP tradizionali:**
| Aspetto | CRL/OCSP | RevocationBitmap2022 |
|---------|----------|---------------------|
| Privacy | CA traccia le verifiche | Nessun tracking |
| Offline | Richiede CA online | Embedded nel DID Doc |
| Velocita | Network roundtrip | O(1) bit lookup |
| Dimensione | Cresce linearmente | Bitmap compresso |

---

### TEST D1: Statistiche Bitmap (Stato Iniziale)

**Cosa testiamo:** Lo stato del bitmap di revoca prima di qualsiasi revoca.

**Perchè è importante:** Verificare che il sistema tenga traccia correttamente delle credenziali emesse e revocate.

**Comando:**
```bash
curl -s "http://localhost:8080/api/v1/revocation/bitmap-stats" | jq .
```

**Output atteso:**
```json
{
  "issuer_did": "did:iota:testnet:0x...",
  "total_credentials_issued": 2,
  "revoked_count": 0,
  "revoked_indices": [],
  "bitmap_size_bytes": 8
}
```

**Spiegazione campi:**
- `total_credentials_issued`: quante credenziali sono state emesse
- `revoked_count`: quante sono state revocate
- `revoked_indices`: lista degli indici revocati

---

### TEST D2: Registra Device per Test Revoca

**Cosa testiamo:** Creiamo un nuovo device specificamente per testare la revoca.

**Perchè è importante:** Usiamo un device dedicato per non influenzare gli altri test.

**Comando:**
```bash
REVOKE_RESPONSE=$(curl -s -X POST "http://localhost:8080/api/v1/device/register" \
    -H "Content-Type: application/json" \
    -d '{
        "public_key": "'$(openssl rand -hex 32)'",
        "device_type": "sensor",
        "capabilities": ["motion"]
    }')

echo "$REVOKE_RESPONSE" | jq .

# Salva i valori
export REVOKE_DID=$(echo "$REVOKE_RESPONSE" | jq -r '.did')
export REVOKE_JWT=$(echo "$REVOKE_RESPONSE" | jq -r '.credential_jwt')

# Estrai l'ID della credenziale e l'indice di revoca dal JWT
export CREDENTIAL_ID=$(echo "$REVOKE_JWT" | cut -d'.' -f2 | tr '_-' '/+' | \
    awk '{while(length($0)%4)$0=$0"=";print}' | base64 -d | \
    jq -r '.vc.id')

export REVOKE_INDEX=$(echo "$REVOKE_JWT" | cut -d'.' -f2 | tr '_-' '/+' | \
    awk '{while(length($0)%4)$0=$0"=";print}' | base64 -d | \
    jq -r '.vc.credentialStatus.revocationBitmapIndex')

echo "Credential ID: $CREDENTIAL_ID"
echo "Revocation Index: $REVOKE_INDEX"
```

---

### TEST D3: Verifica Credential Prima della Revoca

**Cosa testiamo:** Che la credenziale appena creata sia valida.

**Perchè è importante:** Baseline per verificare che la revoca funzioni correttamente.

**Comando:**
```bash
curl -s -X POST "http://localhost:8080/api/v1/credential/verify" \
    -H "Content-Type: application/json" \
    -d "{\"credential_jwt\": \"$REVOKE_JWT\"}" | jq '{valid, revocation_status}'
```

**Output atteso:**
```json
{
  "valid": true,
  "revocation_status": {
    "revoked": false,
    "index": 3
  }
}
```

---

### TEST D4: Revoca Credential On-Chain

**Cosa testiamo:** La revoca di una credenziale usando RevocationBitmap2022.

**Perchè è importante:** Questo e il test centrale della funzionalita di revoca:
1. Il bit corrispondente viene impostato a 1 nel bitmap locale
2. Il bitmap viene serializzato (Roaring -> ZLIB -> Base64)
3. Il DID Document dell'issuer viene aggiornato on-chain con il nuovo bitmap
4. Da questo momento, qualsiasi verifier puo controllare che la credenziale e revocata

**Comando:**
```bash
curl -s -X POST "http://localhost:8080/api/v1/credential/revoke-onchain" \
    -H "Content-Type: application/json" \
    -d "{
        \"credential_id\": \"$CREDENTIAL_ID\",
        \"revocation_index\": $REVOKE_INDEX
    }" | jq .
```

**Output atteso:**
```json
{
  "success": true,
  "credential_id": "urn:uuid:...",
  "revocation_index": 3,
  "revoked_at": "2026-02-03T...",
  "on_chain": true
}
```

**Tempo atteso:** ~7-15 secondi (include transazione blockchain per aggiornare il DID Document)

**Nota:** L'API richiede sia `credential_id` che `revocation_index`. Il `credential_id` e nel formato `urn:uuid:...` e si trova nel campo `vc.id` del JWT.

---

### TEST D5: Verifica Credential Revocata (deve fallire)

**Cosa testiamo:** Che la verifica di una credenziale revocata fallisca.

**Perchè è importante:** Questo e l'effetto pratico della revoca: un verifier che controlla la credenziale deve ricevere un errore.

**Comando:**
```bash
# Pulisci la cache per forzare il recupero del bitmap aggiornato
curl -s -X POST "http://localhost:8080/api/v1/admin/cache/clear" > /dev/null

# Verifica la credenziale revocata
curl -s -X POST "http://localhost:8080/api/v1/credential/verify" \
    -H "Content-Type: application/json" \
    -d "{\"credential_jwt\": \"$REVOKE_JWT\"}" | jq .
```

**Output atteso:**
```json
{
  "valid": false,
  "error": "Credential 'urn:uuid:...' has been revoked: No reason provided"
}
```

---

### TEST D6: Tentativo Doppia Revoca (deve fallire)

**Cosa testiamo:** Che non sia possibile revocare due volte la stessa credenziale.

**Perchè è importante:** Prevenire operazioni ridondanti e potenziali abusi.

**Comando:**
```bash
curl -s -X POST "http://localhost:8080/api/v1/credential/revoke-onchain" \
    -H "Content-Type: application/json" \
    -d "{
        \"credential_id\": \"$CREDENTIAL_ID\",
        \"revocation_index\": $REVOKE_INDEX
    }" | jq .
```

**Output atteso:**
```json
{
  "success": false,
  "error": "Credential at index ... is already revoked"
}
```

---

### TEST D7: Statistiche Bitmap (Dopo Revoca)

**Cosa testiamo:** Che le statistiche riflettano la revoca effettuata.

**Comando:**
```bash
curl -s "http://localhost:8080/api/v1/revocation/bitmap-stats" | jq .
```

**Output atteso:**
```json
{
  "issuer_did": "did:iota:testnet:0x...",
  "total_credentials_issued": 3,
  "revoked_count": 1,
  "revoked_indices": [3],
  "bitmap_size_bytes": 16
}
```

**Note:** 
- `revoked_count` e aumentato
- `revoked_indices` contiene l'indice revocato

---

## Sezione F: Device Client CLI

Questi test verificano il client CLI che gira sui dispositivi IoT.

---

### Prerequisiti Device Client

```bash
# Compila il device client (se non gia fatto)
cd ~/iota-identity-iot
cargo build --release --package device-client

# Verifica che sia compilato
./target/release/device-client --help
```

---

### TEST F1: Registrazione Device via CLI

**Cosa testiamo:** La registrazione di un device usando il CLI invece delle API HTTP.

**Perchè è importante:** Il device client e cio che gira effettivamente sui dispositivi IoT. Deve poter:
1. Generare una coppia di chiavi Ed25519
2. Salvare la chiave privata in modo sicuro
3. Registrarsi presso l'Identity Service
4. Salvare il DID e la credenziale ricevuti

**Comando:**
```bash
# Crea una directory per i dati del device
mkdir -p ./test-device-data

# Registra il device
./target/release/device-client \
    --identity-service "http://localhost:8080" \
    --data-dir "./test-device-data" \
    register \
    --device-type sensor \
    --capabilities "temperature,pressure"
```

**Output atteso:**
```
Device registered successfully!
  DID: did:iota:testnet:0x...
  Object ID: 0x...
  Credential expires: 2027-...

Keys and credentials stored in: ./test-device-data
```

---

### TEST F2: Visualizza Identita Device

**Cosa testiamo:** Il recupero e la visualizzazione dell'identita salvata.

**Perchè è importante:** Verifica che i dati siano stati salvati correttamente e possano essere recuperati.

**Comando:**
```bash
./target/release/device-client \
    --data-dir "./test-device-data" \
    show
```

**Output atteso:**
```
Device Identity:
  DID: did:iota:testnet:0x...
  Public Key: abcdef1234...
  Device Type: Sensor
  Capabilities: ["temperature", "pressure"]
  Credential expires: 2027-...
```

---

### TEST F3: Verifica File Storage

**Cosa testiamo:** Che i file siano stati creati correttamente nella directory specificata.

**Perchè è importante:** Il device deve poter recuperare la sua identita dopo un riavvio.

**Comando:**
```bash
# Verifica i file creati
ls -la ./test-device-data/

# Visualizza l'identita (senza la chiave privata)
cat ./test-device-data/identity.json | jq .

# Verifica che la chiave privata esista (non mostrarla!)
echo "Private key length: $(cat ./test-device-data/private_key.hex | wc -c) chars"
```

**Output atteso:**
```
./test-device-data/:
  -rw------- 1 user user   64 Feb  3 ... private_key.hex
  -rw-r--r-- 1 user user  256 Feb  3 ... identity.json
  -rw-r--r-- 1 user user  850 Feb  3 ... credential.jwt

{
  "did": "did:iota:testnet:0x...",
  "object_id": "0x...",
  "public_key": "...",
  "device_type": "Sensor",
  "capabilities": ["temperature", "pressure"]
}

Private key length: 64 chars
```

---

### TEST F4: Tentativo Doppia Registrazione (deve avvisare)

**Cosa testiamo:** Che il client avvisi se il device e gia registrato.

**Perchè è importante:** Prevenire la creazione accidentale di identita multiple.

**Comando:**
```bash
./target/release/device-client \
    --identity-service "http://localhost:8080" \
    --data-dir "./test-device-data" \
    register \
    --device-type sensor \
    --capabilities "humidity"
```

**Output atteso:**
```
Device already registered!
DID: did:iota:testnet:0x...
Use 'reregister' to create a new identity.
```

---

### TEST F5: Pulizia Dati Device

**Cosa testiamo:** La cancellazione di tutti i dati del device.

**Perchè è importante:** Per dismissione del device o reset completo.

**Comando:**
```bash
./target/release/device-client \
    --data-dir "./test-device-data" \
    clear
```

**Output atteso:**
```
All device data cleared from ./test-device-data
```

**Verifica:**
```bash
./target/release/device-client --data-dir "./test-device-data" show
# Output: Device not registered. Run 'register' first.
```

---

## Sezione G: Test di Persistenza

Questi test verificano che il sistema mantenga lo stato correttamente dopo i restart.

> **NOTA IMPORTANTE: Comportamento della Persistenza**
> 
> L'Identity Service **persiste** l'identita dell'issuer su disco in `~/.iota-identity-service/`.
> Questo significa che dopo un riavvio del servizio:
> - L'issuer mantiene lo **stesso DID** e la stessa chiave di firma
> - L'issuer mantiene il **controllo del DID** (puo modificarlo, revocare credenziali)
> - Le credenziali emesse **rimangono valide** e verificabili
> - Le revoche on-chain **rimangono attive** (sono sulla blockchain)
> 
> Il file `issuer_identity.json` contiene:
> - `signing_key_hex`: chiave per firmare credenziali
> - `tx_key_hex`: chiave per transazioni blockchain (essenziale per mantenere il controllo)
>
> Le chiavi di controllo dei DID dei **device** sono mantenute in memoria e vengono perse
> al riavvio. Questo significa che dopo un riavvio il servizio non puo piu modificare i
> DID dei device creati nella sessione precedente (ma i DID esistono ancora on-chain e
> sono risolvibili).
>
> Il **Device Client** persiste correttamente la sua identita su disco.

---

### TEST G1: Persistenza Issuer Identity e Controllo DID

**Cosa testiamo:** Che l'identita dell'issuer E il controllo del DID persistano dopo un riavvio del servizio.

**Perchè è importante:** L'issuer deve mantenere:
1. La stessa identita (DID + chiave di firma) per garantire che le credenziali rimangano verificabili
2. Il controllo del DID (`has_control: true`) per poter continuare a revocare credenziali on-chain

**Procedura:**

```bash
# 1. PRIMA del restart: salva l'issuer DID e verifica il controllo
echo "Prima del restart:"
ISSUER_STATUS_BEFORE=$(curl -s "http://localhost:8080/api/v1/issuer/status")
ISSUER_BEFORE=$(echo "$ISSUER_STATUS_BEFORE" | jq -r '.issuer_did')
HAS_CONTROL_BEFORE=$(echo "$ISSUER_STATUS_BEFORE" | jq -r '.has_control')
echo "Issuer DID: $ISSUER_BEFORE"
echo "Has Control: $HAS_CONTROL_BEFORE"

# 2. Ferma il servizio (Ctrl+C nel terminale dove gira)

# 3. Riavvia il servizio
cargo run --release --package identity-service

# 4. Verifica che l'issuer sia lo stesso E abbia ancora il controllo DOPO il restart
echo "Dopo il restart:"
ISSUER_STATUS_AFTER=$(curl -s "http://localhost:8080/api/v1/issuer/status")
ISSUER_AFTER=$(echo "$ISSUER_STATUS_AFTER" | jq -r '.issuer_did')
HAS_CONTROL_AFTER=$(echo "$ISSUER_STATUS_AFTER" | jq -r '.has_control')
echo "Issuer DID: $ISSUER_AFTER"
echo "Has Control: $HAS_CONTROL_AFTER"

# 5. Confronta
if [ "$ISSUER_BEFORE" = "$ISSUER_AFTER" ] && [ "$HAS_CONTROL_AFTER" = "true" ]; then
    echo "SUCCESS: Issuer DID e controllo persistiti correttamente!"
else
    echo "ERRORE: Problema con la persistenza"
    echo "  DID match: $([ \"$ISSUER_BEFORE\" = \"$ISSUER_AFTER\" ] && echo 'OK' || echo 'FAIL')"
    echo "  Has Control: $HAS_CONTROL_AFTER (expected: true)"
fi
```

**Output atteso:**
```
Prima del restart:
Issuer DID: did:iota:testnet:0x5fbb3f1d4cf8653e71fddba2269855d13c7eeefe3e02e980db0f75e5b530a984
Has Control: true
Dopo il restart:
Issuer DID: did:iota:testnet:0x5fbb3f1d4cf8653e71fddba2269855d13c7eeefe3e02e980db0f75e5b530a984
Has Control: true
SUCCESS: Issuer DID e controllo persistiti correttamente!
```

---

### TEST G1b: Verifica Persistenza On-Chain (DID Document)

**Cosa testiamo:** Che il DID Document dell'issuer sia ancora sulla blockchain dopo il restart.

**Perchè è importante:** Anche se il servizio viene riavviato, i DID Document esistono sulla blockchain e possono essere risolti da chiunque.

**Comando:**
```bash
# Risolvi il DID Document dell'issuer
ISSUER_DID=$(curl -s "http://localhost:8080/api/v1/issuer/status" | jq -r '.issuer_did')
ISSUER_ENCODED=$(echo -n "$ISSUER_DID" | jq -sRr @uri)

curl -s "http://localhost:8080/api/v1/did/resolve/$ISSUER_ENCODED" | jq '.did_document.id'
```

**Output atteso:**
```
"did:iota:testnet:0x..."
```

---

### TEST G1c: Verifica Credenziali Emesse Prima del Restart

**Cosa testiamo:** Che le credenziali emesse prima del restart siano ancora valide.

**Perchè è importante:** Dimostra che il sistema e realmente decentralizzato - le credenziali non dipendono dalla disponibilita dell'issuer per la verifica.

**Procedura:**
```bash
# Usa una credenziale emessa PRIMA del restart
# (dovresti averla salvata durante i test precedenti in $CREDENTIAL_JWT)

curl -s -X POST "http://localhost:8080/api/v1/credential/verify" \
    -H "Content-Type: application/json" \
    -d "{\"credential_jwt\": \"$CREDENTIAL_JWT\"}" | jq '{valid, issuer}'
```

**Output atteso:**
```json
{
  "valid": true,
  "issuer": "did:iota:testnet:0x..."
}
```

---

### TEST G1d: Verifica Revoca On-Chain Dopo Restart

**Cosa testiamo:** Che sia possibile revocare credenziali on-chain anche dopo un riavvio del servizio.

**Perchè è importante:** Questo e il test critico che dimostra che la persistenza del `tx_key_hex` funziona. Senza questa chiave, il servizio non potrebbe modificare il DID dell'issuer dopo un riavvio.

**Procedura:**
```bash
# 1. Registra un nuovo device
NEW_RESPONSE=$(curl -s -X POST "http://localhost:8080/api/v1/device/register" \
    -H "Content-Type: application/json" \
    -d '{
        "public_key": "'$(openssl rand -hex 32)'",
        "device_type": "sensor",
        "capabilities": ["test-persistence"]
    }')

NEW_JWT=$(echo "$NEW_RESPONSE" | jq -r '.credential_jwt')

NEW_CREDENTIAL_ID=$(echo "$NEW_JWT" | cut -d'.' -f2 | tr '_-' '/+' | \
    awk '{while(length($0)%4)$0=$0"=";print}' | base64 -d | \
    jq -r '.vc.id')

NEW_REVOKE_INDEX=$(echo "$NEW_JWT" | cut -d'.' -f2 | tr '_-' '/+' | \
    awk '{while(length($0)%4)$0=$0"=";print}' | base64 -d | \
    jq -r '.vc.credentialStatus.revocationBitmapIndex')

echo "New Credential ID: $NEW_CREDENTIAL_ID"
echo "New Revocation Index: $NEW_REVOKE_INDEX"

# 2. Revoca la credenziale (questo richiede il controllo del DID)
curl -s -X POST "http://localhost:8080/api/v1/credential/revoke-onchain" \
    -H "Content-Type: application/json" \
    -d "{
        \"credential_id\": \"$NEW_CREDENTIAL_ID\",
        \"revocation_index\": $NEW_REVOKE_INDEX
    }" | jq .
```

**Output atteso:**
```json
{
  "success": true,
  "credential_id": "urn:uuid:...",
  "revocation_index": ...,
  "revoked_at": "2026-...",
  "on_chain": true
}
```

**Se `on_chain: true`, la persistenza del controllo funziona correttamente!**

---

### TEST G2: Persistenza Identita Device Client

**Cosa testiamo:** Che l'identita del device sopravviva al restart del client.

**Perchè è importante:** Il device deve poter spegnersi e riaccendersi mantenendo la sua identita.

**Procedura:**
```bash
# 1. Registra un device
mkdir -p ./persist-test
./target/release/device-client \
    --identity-service "http://localhost:8080" \
    --data-dir "./persist-test" \
    register --device-type sensor --capabilities "temperature"

# 2. Verifica i file creati
ls -la ./persist-test/

# 3. Simula "restart" del device (nuovo processo)
./target/release/device-client \
    --data-dir "./persist-test" \
    show

# 4. Cleanup
rm -rf ./persist-test
```

**Output atteso:**
```
./persist-test/:
  identity.json
  credential.jwt
  private_key.hex

Device Identity:
  DID: did:iota:testnet:0x...
  ...
```

---

## Sezione H: Validazione Input

Questi test verificano che il sistema gestisca correttamente input invalidi.

---

### TEST H1: Public Key Invalida

**Cosa testiamo:** Rifiuto di chiavi pubbliche malformate.

**Comando:**
```bash
# Chiave troppo corta
echo "Test chiave troppo corta:"
curl -s -X POST "http://localhost:8080/api/v1/device/register" \
    -H "Content-Type: application/json" \
    -d '{"public_key": "tooshort", "device_type": "sensor", "capabilities": []}' | jq .

# Chiave con caratteri non hex
echo "Test chiave non-hex:"
curl -s -X POST "http://localhost:8080/api/v1/device/register" \
    -H "Content-Type: application/json" \
    -d '{"public_key": "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "device_type": "sensor", "capabilities": []}' | jq .
```

**Output atteso:**
```json
{
  "error": "Invalid public key: ..."
}
```

---

### TEST H2: DID Malformato

**Cosa testiamo:** Rifiuto di DID con formato invalido.

**Comando:**
```bash
curl -s "http://localhost:8080/api/v1/did/resolve/not-a-valid-did" | jq .
```

**Output atteso:**
```json
{
  "error": "Invalid DID format: ..."
}
```

---

### TEST H3: DID Inesistente

**Cosa testiamo:** Gestione di DID che non esistono on-chain.

**Comando:**
```bash
NONEXISTENT_DID="did:iota:testnet:0x1111111111111111111111111111111111111111111111111111111111111111"
NONEXISTENT_ENCODED=$(echo -n "$NONEXISTENT_DID" | jq -sRr @uri)

curl -s "http://localhost:8080/api/v1/did/resolve/$NONEXISTENT_ENCODED" | jq .
```

**Output atteso:**
```json
{
  "error": "DID resolution failed: ..."
}
```

---

### TEST H4: JWT Malformato

**Cosa testiamo:** Rifiuto di JWT con struttura invalida.

**Comando:**
```bash
curl -s -X POST "http://localhost:8080/api/v1/credential/verify" \
    -H "Content-Type: application/json" \
    -d '{"credential_jwt": "not.a.jwt"}' | jq .
```

**Output atteso:**
```json
{
  "valid": false,
  "error": "Invalid JWT..."
}
```

---

### TEST H5: Revoca con Parametri Mancanti

**Cosa testiamo:** Rifiuto di richieste di revoca incomplete.

**Comando:**
```bash
# Manca credential_id
echo "Test manca credential_id:"
curl -s -X POST "http://localhost:8080/api/v1/credential/revoke-onchain" \
    -H "Content-Type: application/json" \
    -d '{"revocation_index": 1}'

# Manca revocation_index
echo "Test manca revocation_index:"
curl -s -X POST "http://localhost:8080/api/v1/credential/revoke-onchain" \
    -H "Content-Type: application/json" \
    -d '{"credential_id": "urn:uuid:test"}'
```

**Output atteso:**
```
Test manca credential_id:
Failed to deserialize the JSON body into the target type: missing field `credential_id`...

Test manca revocation_index:
Failed to deserialize the JSON body into the target type: missing field `revocation_index`...
```

---

### TEST H6: Indice di Revoca Non Valido

**Cosa testiamo:** Rifiuto di indici di revoca non esistenti.

**Comando:**
```bash
# Indice molto grande (non emesso)
curl -s -X POST "http://localhost:8080/api/v1/credential/revoke-onchain" \
    -H "Content-Type: application/json" \
    -d '{"credential_id": "urn:uuid:test", "revocation_index": 999999}' | jq .
```

**Output atteso:**
```json
{
  "success": false,
  "error": "Invalid revocation index..."
}
```

---

## Sezione I: TLS con Autenticazione DID

Questi test verificano la comunicazione TLS sicura tra dispositivi con autenticazione basata su DID. 

> **PREREQUISITO:** Completa la **Sezione E** (Inizializzazione Issuer) prima di eseguire questi test.
> L'autenticazione TLS richiede che le credenziali siano verificabili on-chain.

---

### TEST I1: Setup - Registra Server Device

**Cosa testiamo:** La registrazione di un device che fara da server TLS.

**Terminale 2:**
```bash
rm -rf ./server-device ./client-device

mkdir -p ./server-device

./target/release/device-client \
    --identity-service "http://localhost:8080" \
    --data-dir "./server-device" \
    register \
    --device-type gateway \
    --capabilities "routing,firewall"
```

**Output atteso:**
```
Device registered successfully!
  DID: did:iota:testnet:0x...
  ...
```

---

### TEST I2: Setup - Registra Client Device

**Cosa testiamo:** La registrazione di un device che fara da client TLS.

**Terminale 3:**
```bash
mkdir -p ./client-device

./target/release/device-client \
    --identity-service "http://localhost:8080" \
    --data-dir "./client-device" \
    register \
    --device-type sensor \
    --capabilities "temperature"
```

**Output atteso:**
```
Device registered successfully!
  DID: did:iota:testnet:0x...
  ...
```

---

### TEST I3: Avvia Server TLS

**Cosa testiamo:** L'avvio del server TLS con autenticazione DID.

**Terminale 2:**
```bash
./target/release/device-client \
    --identity-service "http://localhost:8080" \
    --data-dir "./server-device" \
    server \
    --port 8443
```

**Output atteso:**
```
Server listening on port 8443
  DID: did:iota:testnet:0x...
```

Il server rimarra in attesa di connessioni.

---

### TEST I4: Connessione Client -> Server

**Cosa testiamo:** Connessione TLS con autenticazione DID reciproca.

**Perchè è importante:** Questo e il test principale che verifica:
1. TLS handshake funzionante
2. Scambio di credenziali
3. Verifica firma JWT contro la chiave dell'issuer on-chain
4. Challenge-response per provare possesso chiavi
5. Verifica revoca

**Terminale 3:**
```bash
./target/release/device-client \
    --identity-service "http://localhost:8080" \
    --data-dir "./client-device" \
    connect \
    --addr "localhost:8443"
```

**Output atteso (Client - Terminale 3):**
```
Connected and authenticated!
  Peer DID: did:iota:testnet:0x...
  Peer Public Key: abcdef12...

  Metrics:
    TLS Handshake: 0ms
    DID Auth: 125ms
    Credential Verify: 36ms
    Challenge-Response: 0ms
    Total: 127ms
```

**Output atteso (Server - Terminale 2):**
```
New connection from 127.0.0.1:...
  Authenticated client: did:iota:testnet:0x...
```

---

### TEST I5: Connessione con Device Non Registrato (deve fallire)

**Cosa testiamo:** Che un device senza identita valida non possa connettersi.

**Perchè è importante:** Verifica che il sistema rifiuti connessioni non autorizzate.

**Terminale 3:**
```bash
# Crea un device senza registrarlo
mkdir -p ./unregistered-device

./target/release/device-client \
    --data-dir "./unregistered-device" \
    connect \
    --addr "localhost:8443"
```

**Output atteso:**
```
Error: Device not registered. Run 'register' first.
```

---

### TEST I6: Connessioni Multiple

**Cosa testiamo:** Che il server possa gestire piu connessioni in sequenza.

**Perchè è importante:** In un ambiente reale, un gateway ricevera connessioni da molti sensori.

**Terminale 3:**
```bash
# Esegui 3 connessioni in sequenza
for i in 1 2 3; do
    echo "=== Connection $i ==="
    ./target/release/device-client \
        --identity-service "http://localhost:8080" \
        --data-dir "./client-device" \
        connect \
        --addr "localhost:8443"
    sleep 1
done
```

**Output atteso (Server):**
```
  Authenticated client: did:iota:testnet:0x...
  Authenticated client: did:iota:testnet:0x...
  Authenticated client: did:iota:testnet:0x...
```

---

### TEST I7: Verifica Metriche di Performance

**Cosa testiamo:** Raccolta dei tempi di autenticazione per analisi.

**Perchè è importante:** Questi dati sono fondamentali per la tesi perche permettono di confrontare le performance con PKI tradizionale.

**Terminale 3:**
```bash
# Esegui 10 connessioni e raccogli le metriche
echo "Run,TLS_ms,DIDAuth_ms,CredVerify_ms,Challenge_ms,Total_ms" > tls_metrics.csv

for i in $(seq 1 10); do
    OUTPUT=$(./target/release/device-client \
        --identity-service "http://localhost:8080" \
        --data-dir "./client-device" \
        connect \
        --addr "localhost:8443" 2>&1)
    
    TLS=$(echo "$OUTPUT" | grep "TLS Handshake" | awk '{print $3}' | tr -d 'ms')
    DID=$(echo "$OUTPUT" | grep "DID Auth" | awk '{print $3}' | tr -d 'ms')
    CRED=$(echo "$OUTPUT" | grep "Credential Verify" | awk '{print $3}' | tr -d 'ms')
    CHALLENGE=$(echo "$OUTPUT" | grep "Challenge-Response" | awk '{print $2}' | tr -d 'ms')
    TOTAL=$(echo "$OUTPUT" | grep "Total:" | awk '{print $2}' | tr -d 'ms')
    
    echo "$i,$TLS,$DID,$CRED,$CHALLENGE,$TOTAL" >> tls_metrics.csv
    sleep 0.5
done

echo "Metrics saved to tls_metrics.csv"
cat tls_metrics.csv
```

**Output atteso:**
```csv
Run,TLS_ms,DIDAuth_ms,CredVerify_ms,Challenge_ms,Total_ms
1,0,125,36,0,127
2,0,118,32,0,120
3,0,122,35,0,125
...
```

**Note sulle performance:**
- TLS Handshake: ~0ms (connessione locale)
- DID Auth: ~120ms (include risoluzione DID, verifica JWT, challenge-response)
- Credential Verify: ~35ms (verifica firma contro chiave on-chain)
- Total: ~125ms (molto piu veloce delle verifiche OCSP ripetute)

---

### TEST I8: Test con Credential Revocata (deve fallire)

**Cosa testiamo:** Che un device con credential revocata venga rifiutato.

**Perchè è importante:** Dimostra che il sistema di revoca funziona end-to-end nelle connessioni TLS.

**Preparazione (Terminale 3):**
```bash
# Registra un nuovo device che poi revocheremo
rm -rf ./revoked-device
mkdir -p ./revoked-device

./target/release/device-client \
    --identity-service "http://localhost:8080" \
    --data-dir "./revoked-device" \
    register \
    --device-type sensor \
    --capabilities "test"

# Estrai credential_id e indice di revoca
REVOKE_JWT=$(cat ./revoked-device/credential.jwt)

REVOKE_CREDENTIAL_ID=$(echo "$REVOKE_JWT" | cut -d'.' -f2 | tr '_-' '/+' | \
    awk '{while(length($0)%4)$0=$0"=";print}' | base64 -d | \
    jq -r '.vc.id')

REVOKE_INDEX=$(echo "$REVOKE_JWT" | cut -d'.' -f2 | tr '_-' '/+' | \
    awk '{while(length($0)%4)$0=$0"=";print}' | base64 -d | \
    jq -r '.vc.credentialStatus.revocationBitmapIndex')

echo "Credential ID: $REVOKE_CREDENTIAL_ID"
echo "Revocation index: $REVOKE_INDEX"

# Revoca la credenziale
curl -s -X POST "http://localhost:8080/api/v1/credential/revoke-onchain" \
    -H "Content-Type: application/json" \
    -d "{
        \"credential_id\": \"$REVOKE_CREDENTIAL_ID\",
        \"revocation_index\": $REVOKE_INDEX
    }" | jq .
```

**Dopo la revoca, tentativo di connessione:**
```bash
./target/release/device-client \
    --identity-service "http://localhost:8080" \
    --data-dir "./revoked-device" \
    connect \
    --addr "localhost:8443"
```

**Output atteso nel terminale 2:**
```
Authentication failed: Credential 'index:x' has been revoked: Credential has been revoked
```

---

### TEST I9: Cleanup

**Cosa testiamo:** Pulizia dei dati di test.

**Comando:**
```bash
# Ferma il server (Ctrl+C nel Terminale 2)

# Pulisci le directory di test
rm -rf ./server-device ./client-device ./unregistered-device ./revoked-device
rm -f tls_metrics.csv

echo "Cleanup completato"
```

---

## Riepilogo Architettura

```
+---------------------------------------------------------------------+
|                    ARCHITETTURA DEL SISTEMA                         |
+---------------------------------------------------------------------+
|                                                                     |
|  IoT Device                    Identity Service         Blockchain  |
|  +----------+                  +--------------+        +---------+  |
|  | Device   | --register--->   | DID Manager  | -----> |  IOTA   |  |
|  | Client   |                  |              |        | Rebased |  |
|  |          | <--DID+JWT-----  | Credential   | <----- |         |  |
|  |          |                  | Issuer       |        |         |  |
|  +----------+                  |              |        |         |  |
|       |                        | Revocation   |        |         |  |
|       |                        | Manager      |        |         |  |
|       v                        +--------------+        +---------+  |
|  +----------+                         |                     ^       |
|  | Verifier | <--resolve DID----------+                     |       |
|  |          | <--check bitmap-------------------------------+       |
|  +----------+                                                       |
|                                                                     |
|  FLUSSO:                                                            |
|  1. Device genera keypair Ed25519                                   |
|  2. Device si registra -> Identity Service crea DID on-chain        |
|  3. Device riceve DID + Verifiable Credential (JWT)                 |
|  4. Verifier risolve DID dell'issuer dalla blockchain               |
|  5. Verifier verifica firma + controlla revocation bitmap           |
|                                                                     |
|  FLUSSO TLS + DID AUTH:                                             |
|  1. Client <-> Server: TLS 1.3 Handshake                            |
|  2. Client -> Server: Hello (DID, JWT, pubkey, challenge)           |
|  3. Server verifica JWT + risponde con proprio Hello + response     |
|  4. Client verifica JWT + invia response                            |
|  5. Server conferma -> Canale autenticato                           |
|                                                                     |
|  STORAGE:                                                           |
|  - Issuer identity: ~/.iota-identity-service/issuer_identity.json   |
|    (contiene: did, signing_key_hex, tx_key_hex, fragment)           |
|  - Device identity: <data-dir>/identity.json, credential.jwt,       |
|                     private_key.hex                                 |
|                                                                     |
+---------------------------------------------------------------------+
```

---

## Checklist Finale

Dopo aver completato tutti i test, dovresti aver verificato:

-  **Sezione A:** Servizio attivo e metriche funzionanti
-  **Sezione E:** Inizializzazione issuer on-chain con persistenza completa (DID + controllo)
-  **Sezione B:** Creazione, risoluzione, rotazione e disattivazione DID
-  **Sezione C:** Emissione e verifica Verifiable Credentials
-  **Sezione D:** Revoca on-chain con RevocationBitmap2022 (richiede credential_id + revocation_index)
-  **Sezione F:** Device Client CLI funzionante
-  **Sezione G:** Persistenza dei dati dopo restart (issuer con controllo + device)
-  **Sezione H:** Validazione input e gestione errori
-  **Sezione I:** TLS con autenticazione DID (~127ms per connessione)

---

*Versione: 2.0 - Febbraio 2026*
