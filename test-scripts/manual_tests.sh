#!/bin/bash
# test_complete_system.sh
# Test completo di tutte le funzionalità del sistema

set -e

BASE_URL="http://localhost:8080"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=============================================="
echo "  IOTA Identity IoT - Test Completo"
echo "=============================================="

# 1. Health Check
echo -e "\n${YELLOW}[1/10] Health Check${NC}"
HEALTH=$(curl -s "$BASE_URL/health")
echo "$HEALTH" | jq .
if echo "$HEALTH" | jq -e '.status == "healthy"' > /dev/null; then
    echo -e "${GREEN}✓ Health check passed${NC}"
else
    echo -e "${RED}✗ Health check failed${NC}"
    exit 1
fi

# 2. Registrazione Device
echo -e "\n${YELLOW}[2/10] Registrazione Device${NC}"
DEVICE_KEY=$(openssl rand -hex 32)
echo "Public Key: $DEVICE_KEY"

REGISTER_RESPONSE=$(curl -s -X POST "$BASE_URL/api/v1/device/register" \
    -H "Content-Type: application/json" \
    -d "{
        \"public_key\": \"$DEVICE_KEY\",
        \"device_type\": \"sensor\",
        \"capabilities\": [\"temperature\", \"humidity\"]
    }")

echo "$REGISTER_RESPONSE" | jq .

DID=$(echo "$REGISTER_RESPONSE" | jq -r '.identity.did')
CREDENTIAL_ID=$(echo "$REGISTER_RESPONSE" | jq -r '.credential.id')

if [ "$DID" != "null" ] && [ -n "$DID" ]; then
    echo -e "${GREEN}✓ Device registered successfully${NC}"
    echo "  DID: $DID"
    echo "  Credential ID: $CREDENTIAL_ID"
else
    echo -e "${RED}✗ Device registration failed${NC}"
    exit 1
fi

# 3. Risoluzione DID
echo -e "\n${YELLOW}[3/10] Risoluzione DID${NC}"
DID_ENCODED=$(echo -n "$DID" | jq -sRr @uri)
RESOLVE_RESPONSE=$(curl -s "$BASE_URL/api/v1/did/resolve/$DID_ENCODED")
echo "$RESOLVE_RESPONSE" | jq '.id, .verificationMethod[0].id' 2>/dev/null || echo "$RESOLVE_RESPONSE"

if echo "$RESOLVE_RESPONSE" | jq -e '.id' > /dev/null 2>&1; then
    echo -e "${GREEN}✓ DID resolved successfully${NC}"
    
    # Link IOTA Explorer
    OBJECT_ID=$(echo "$DID" | sed 's/did:iota:testnet://')
    echo -e "  Explorer: https://explorer.rebased.iota.org/object/${OBJECT_ID}?network=testnet"
else
    echo -e "${RED}✗ DID resolution failed${NC}"
fi

# 4. Verifica Credential (valida)
echo -e "\n${YELLOW}[4/10] Verifica Credential (valida)${NC}"
CREDENTIAL_JWT=$(echo "$REGISTER_RESPONSE" | jq -r '.credential.jwt')

VERIFY_RESPONSE=$(curl -s -X POST "$BASE_URL/api/v1/credential/verify" \
    -H "Content-Type: application/json" \
    -d "{\"credential_jwt\": \"$CREDENTIAL_JWT\"}")

echo "$VERIFY_RESPONSE" | jq .

if echo "$VERIFY_RESPONSE" | jq -e '.valid == true' > /dev/null; then
    echo -e "${GREEN}✓ Credential verification passed${NC}"
else
    echo -e "${RED}✗ Credential verification failed${NC}"
fi

# 5. Status Credential (prima della revoca)
echo -e "\n${YELLOW}[5/10] Status Credential (pre-revoca)${NC}"
CRED_ID_ENCODED=$(echo -n "$CREDENTIAL_ID" | jq -sRr @uri)
STATUS_RESPONSE=$(curl -s "$BASE_URL/api/v1/credential/status/$CRED_ID_ENCODED")
echo "$STATUS_RESPONSE" | jq .

if echo "$STATUS_RESPONSE" | jq -e '.revoked == false' > /dev/null; then
    echo -e "${GREEN}✓ Credential is active (not revoked)${NC}"
else
    echo -e "${YELLOW}! Credential status unexpected${NC}"
fi

# 6. Revoca Credential (in-memory)
echo -e "\n${YELLOW}[6/10] Revoca Credential (in-memory)${NC}"
REVOKE_RESPONSE=$(curl -s -X POST "$BASE_URL/api/v1/credential/revoke" \
    -H "Content-Type: application/json" \
    -d "{
        \"credential_id\": \"$CREDENTIAL_ID\",
        \"reason\": \"Test revocation\"
    }")

echo "$REVOKE_RESPONSE" | jq .

if echo "$REVOKE_RESPONSE" | jq -e '.success == true' > /dev/null; then
    echo -e "${GREEN}✓ Credential revoked successfully${NC}"
else
    echo -e "${RED}✗ Credential revocation failed${NC}"
fi

# 7. Status Credential (dopo revoca)
echo -e "\n${YELLOW}[7/10] Status Credential (post-revoca)${NC}"
STATUS_RESPONSE2=$(curl -s "$BASE_URL/api/v1/credential/status/$CRED_ID_ENCODED")
echo "$STATUS_RESPONSE2" | jq .

if echo "$STATUS_RESPONSE2" | jq -e '.revoked == true' > /dev/null; then
    echo -e "${GREEN}✓ Credential correctly shows as revoked${NC}"
else
    echo -e "${RED}✗ Credential should be revoked${NC}"
fi

# 8. Key Rotation (on-chain)
echo -e "\n${YELLOW}[8/10] Key Rotation (on-chain)${NC}"
NEW_KEY=$(openssl rand -hex 32)
echo "New Public Key: $NEW_KEY"

ROTATE_RESPONSE=$(curl -s -X POST "$BASE_URL/api/v1/did/rotate-key/$DID_ENCODED" \
    -H "Content-Type: application/json" \
    -d "{\"new_public_key\": \"$NEW_KEY\"}")

echo "$ROTATE_RESPONSE" | jq .

if echo "$ROTATE_RESPONSE" | jq -e '.success == true' > /dev/null; then
    echo -e "${GREEN}✓ Key rotation successful${NC}"
    NEW_METHOD=$(echo "$ROTATE_RESPONSE" | jq -r '.new_verification_method_id')
    echo "  New verification method: $NEW_METHOD"
    
    # Verifica che il DID abbia ora 2 verification methods
    echo -e "\n  Verifying DID Document has new key..."
    sleep 2
    RESOLVE_AFTER=$(curl -s "$BASE_URL/api/v1/did/resolve/$DID_ENCODED")
    METHOD_COUNT=$(echo "$RESOLVE_AFTER" | jq '.verificationMethod | length')
    echo "  Verification methods count: $METHOD_COUNT"
    
    if [ "$METHOD_COUNT" -ge 2 ]; then
        echo -e "${GREEN}✓ DID Document updated with new key${NC}"
    fi
else
    echo -e "${RED}✗ Key rotation failed${NC}"
    echo "$ROTATE_RESPONSE"
fi

# 9. Registra secondo device (per test deactivation)
echo -e "\n${YELLOW}[9/10] Registrazione secondo device per test deactivation${NC}"
DEVICE_KEY2=$(openssl rand -hex 32)

REGISTER_RESPONSE2=$(curl -s -X POST "$BASE_URL/api/v1/device/register" \
    -H "Content-Type: application/json" \
    -d "{
        \"public_key\": \"$DEVICE_KEY2\",
        \"device_type\": \"actuator\",
        \"capabilities\": [\"relay\"]
    }")

DID2=$(echo "$REGISTER_RESPONSE2" | jq -r '.identity.did')
echo "Second DID: $DID2"

if [ "$DID2" != "null" ] && [ -n "$DID2" ]; then
    echo -e "${GREEN}✓ Second device registered${NC}"
else
    echo -e "${RED}✗ Second device registration failed${NC}"
    exit 1
fi

# 10. DID Deactivation (on-chain)
echo -e "\n${YELLOW}[10/10] DID Deactivation (on-chain)${NC}"
DID2_ENCODED=$(echo -n "$DID2" | jq -sRr @uri)

DEACTIVATE_RESPONSE=$(curl -s -X POST "$BASE_URL/api/v1/did/deactivate/$DID2_ENCODED")

echo "$DEACTIVATE_RESPONSE" | jq .

if echo "$DEACTIVATE_RESPONSE" | jq -e '.success == true' > /dev/null; then
    echo -e "${GREEN}✓ DID deactivation successful${NC}"
    
    # Verifica che il DID sia deactivated
    OBJECT_ID2=$(echo "$DID2" | sed 's/did:iota:testnet://')
    echo -e "  Explorer: https://explorer.rebased.iota.org/object/${OBJECT_ID2}?network=testnet"
    
    # Test doppia deactivation (deve fallire)
    echo -e "\n  Testing double deactivation (should fail)..."
    DEACTIVATE2=$(curl -s -X POST "$BASE_URL/api/v1/did/deactivate/$DID2_ENCODED")
    if echo "$DEACTIVATE2" | jq -e '.success == false' > /dev/null; then
        echo -e "${GREEN}✓ Double deactivation correctly rejected${NC}"
    fi
else
    echo -e "${RED}✗ DID deactivation failed${NC}"
    echo "$DEACTIVATE_RESPONSE"
fi

# Riepilogo
echo -e "\n=============================================="
echo -e "  ${GREEN}TEST COMPLETATI${NC}"
echo "=============================================="
echo ""
echo "DIDs creati:"
echo "  1. $DID (con key rotation)"
echo "  2. $DID2 (deactivated)"
echo ""
echo "Verifica su IOTA Explorer:"
OBJECT_ID1=$(echo "$DID" | sed 's/did:iota:testnet://')
OBJECT_ID2=$(echo "$DID2" | sed 's/did:iota:testnet://')
echo "  https://explorer.rebased.iota.org/object/${OBJECT_ID1}?network=testnet"
echo "  https://explorer.rebased.iota.org/object/${OBJECT_ID2}?network=testnet"
echo ""
echo "Cache stats:"
curl -s "$BASE_URL/health" | jq '.cache_stats // "N/A"'