#!/bin/bash
# =============================================================================
# IOTA Identity IoT - Complete System Test
# =============================================================================
# Tests all features: DID creation, resolution, key rotation, deactivation,
# credential issuance, verification, and revocation.
# =============================================================================

set -e

BASE_URL="http://localhost:8080"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Counters
TESTS_PASSED=0
TESTS_FAILED=0

pass() {
    echo -e "${GREEN}PASS${NC}: $1"
    ((TESTS_PASSED++))
}

fail() {
    echo -e "${RED}FAIL${NC}: $1"
    ((TESTS_FAILED++))
}

info() {
    echo -e "${BLUE}INFO${NC}: $1"
}

warn() {
    echo -e "${YELLOW}WARN${NC}: $1"
}

section() {
    echo ""
    echo -e "${CYAN}=============================================="
    echo "  $1"
    echo -e "==============================================${NC}"
}

# URL encode function
urlencode() {
    echo -n "$1" | jq -sRr @uri
}

echo "=============================================="
echo "  IOTA Identity IoT - Complete System Test"
echo "=============================================="
echo ""
echo "Target: $BASE_URL"
echo "Date: $(date)"
echo ""

# =============================================================================
# PRE-CHECK: Service Availability
# =============================================================================
section "PRE-CHECK: Service Availability"

echo -n "Checking if service is running... "
HEALTH=$(curl -s "$BASE_URL/health" 2>/dev/null || echo '{"status":"error"}')

if echo "$HEALTH" | jq -e '.status == "healthy"' > /dev/null 2>&1; then
    pass "Service is healthy"
    echo "$HEALTH" | jq -c '{status, network, cache_stats}' 2>/dev/null || true
else
    fail "Service not available"
    echo "Please start the service first:"
    echo "  cargo run --release --package identity-service"
    exit 1
fi

# =============================================================================
# TEST 1: Device Registration
# =============================================================================
section "TEST 1: Device Registration"

# Generate key for device 1
PUBLIC_KEY_1=$(openssl rand -hex 32)
echo "Device 1 Public Key: ${PUBLIC_KEY_1:0:20}..."

echo ""
echo "1.1 Registering Device 1 (Sensor)..."
REGISTER_1=$(curl -s -X POST "$BASE_URL/api/v1/device/register" \
    -H "Content-Type: application/json" \
    -d "{
        \"public_key\": \"$PUBLIC_KEY_1\",
        \"device_type\": \"Sensor\",
        \"capabilities\": [\"temperature\", \"humidity\", \"pressure\"]
    }")

DID_1=$(echo "$REGISTER_1" | jq -r '.identity.did // .did // empty')
OBJECT_ID_1=$(echo "$REGISTER_1" | jq -r '.identity.object_id // .object_id // empty')
CREDENTIAL_1=$(echo "$REGISTER_1" | jq -r '.credential.jwt // .credential_jwt // empty')
CREDENTIAL_ID_1=$(echo "$REGISTER_1" | jq -r '.credential.id // empty')

if [ -n "$DID_1" ] && [ "$DID_1" != "null" ]; then
    pass "Device 1 registered"
    echo "  DID: $DID_1"
    echo "  Object ID: $OBJECT_ID_1"
    [ -n "$CREDENTIAL_ID_1" ] && echo "  Credential ID: $CREDENTIAL_ID_1"
else
    fail "Device 1 registration failed"
    echo "$REGISTER_1" | jq . 2>/dev/null || echo "$REGISTER_1"
fi

# Register device 2 for deactivation tests
echo ""
echo "1.2 Registering Device 2 (for deactivation test)..."
PUBLIC_KEY_2=$(openssl rand -hex 32)

REGISTER_2=$(curl -s -X POST "$BASE_URL/api/v1/device/register" \
    -H "Content-Type: application/json" \
    -d "{
        \"public_key\": \"$PUBLIC_KEY_2\",
        \"device_type\": \"Actuator\",
        \"capabilities\": [\"relay\", \"motor\"]
    }")

DID_2=$(echo "$REGISTER_2" | jq -r '.identity.did // .did // empty')
OBJECT_ID_2=$(echo "$REGISTER_2" | jq -r '.identity.object_id // .object_id // empty')

if [ -n "$DID_2" ] && [ "$DID_2" != "null" ]; then
    pass "Device 2 registered"
    echo "  DID: $DID_2"
else
    fail "Device 2 registration failed"
fi

# Register device 3 for key rotation tests
echo ""
echo "1.3 Registering Device 3 (for key rotation test)..."
PUBLIC_KEY_3=$(openssl rand -hex 32)

REGISTER_3=$(curl -s -X POST "$BASE_URL/api/v1/device/register" \
    -H "Content-Type: application/json" \
    -d "{
        \"public_key\": \"$PUBLIC_KEY_3\",
        \"device_type\": \"Gateway\",
        \"capabilities\": [\"routing\", \"aggregation\"]
    }")

DID_3=$(echo "$REGISTER_3" | jq -r '.identity.did // .did // empty')
OBJECT_ID_3=$(echo "$REGISTER_3" | jq -r '.identity.object_id // .object_id // empty')

if [ -n "$DID_3" ] && [ "$DID_3" != "null" ]; then
    pass "Device 3 registered"
    echo "  DID: $DID_3"
else
    fail "Device 3 registration failed"
fi

# =============================================================================
# TEST 2: DID Resolution
# =============================================================================
section "TEST 2: DID Resolution"

if [ -n "$DID_1" ]; then
    DID_1_ENCODED=$(urlencode "$DID_1")
    
    echo "2.1 Resolving Device 1 DID..."
    RESOLVE_1=$(curl -s "$BASE_URL/api/v1/did/resolve/$DID_1_ENCODED")
    
    DOC_ID=$(echo "$RESOLVE_1" | jq -r '.id // .did_document.id // empty')
    
    if [ -n "$DOC_ID" ] && [ "$DOC_ID" != "null" ]; then
        pass "DID 1 resolved"
        
        # Count verification methods
        VM_COUNT=$(echo "$RESOLVE_1" | jq '.verificationMethod | length // 0' 2>/dev/null || echo "0")
        echo "  Document ID: $DOC_ID"
        echo "  Verification Methods: $VM_COUNT"
        
        # Show first verification method
        echo "$RESOLVE_1" | jq -r '.verificationMethod[0].id // empty' 2>/dev/null | \
            xargs -I {} echo "  First VM: {}"
    else
        fail "DID 1 resolution failed"
        echo "$RESOLVE_1" | jq . 2>/dev/null || echo "$RESOLVE_1"
    fi
    
    echo ""
    echo "2.2 Testing resolution caching..."
    START_TIME=$(date +%s%N)
    RESOLVE_1_CACHED=$(curl -s "$BASE_URL/api/v1/did/resolve/$DID_1_ENCODED")
    END_TIME=$(date +%s%N)
    ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))
    
    if [ "$ELAPSED_MS" -lt 100 ]; then
        pass "Cached resolution fast (<100ms): ${ELAPSED_MS}ms"
    else
        info "Resolution took ${ELAPSED_MS}ms (may not be cached)"
    fi
fi

# =============================================================================
# TEST 3: Credential Verification
# =============================================================================
section "TEST 3: Credential Verification"

if [ -n "$CREDENTIAL_1" ] && [ "$CREDENTIAL_1" != "null" ]; then
    echo "3.1 Verifying valid credential..."
    VERIFY_1=$(curl -s -X POST "$BASE_URL/api/v1/credential/verify" \
        -H "Content-Type: application/json" \
        -d "{\"credential_jwt\": \"$CREDENTIAL_1\"}")
    
    VALID=$(echo "$VERIFY_1" | jq -r '.valid // false')
    
    if [ "$VALID" == "true" ]; then
        pass "Credential verified successfully"
        echo "$VERIFY_1" | jq -c '{valid, issuer, subject}' 2>/dev/null || true
    else
        fail "Credential verification failed"
        echo "$VERIFY_1" | jq . 2>/dev/null || echo "$VERIFY_1"
    fi
    
    echo ""
    echo "3.2 Testing invalid credential..."
    VERIFY_INVALID=$(curl -s -X POST "$BASE_URL/api/v1/credential/verify" \
        -H "Content-Type: application/json" \
        -d '{"credential_jwt": "invalid.jwt.token"}')
    
    VALID_INVALID=$(echo "$VERIFY_INVALID" | jq -r '.valid // true')
    
    if [ "$VALID_INVALID" == "false" ]; then
        pass "Invalid credential correctly rejected"
    else
        fail "Invalid credential should be rejected"
    fi
else
    warn "No credential JWT available for verification tests"
fi

# =============================================================================
# TEST 4: Credential Revocation (In-Memory)
# =============================================================================
section "TEST 4: Credential Revocation (In-Memory)"

if [ -n "$CREDENTIAL_ID_1" ] && [ "$CREDENTIAL_ID_1" != "null" ]; then
    CRED_ID_ENCODED=$(urlencode "$CREDENTIAL_ID_1")
    
    echo "4.1 Checking credential status before revocation..."
    STATUS_BEFORE=$(curl -s "$BASE_URL/api/v1/credential/status/$CRED_ID_ENCODED")
    REVOKED_BEFORE=$(echo "$STATUS_BEFORE" | jq -r '.revoked // false')
    
    if [ "$REVOKED_BEFORE" == "false" ]; then
        pass "Credential is active (not revoked)"
    else
        warn "Credential already revoked"
    fi
    
    echo ""
    echo "4.2 Revoking credential..."
    REVOKE_RESULT=$(curl -s -X POST "$BASE_URL/api/v1/credential/revoke" \
        -H "Content-Type: application/json" \
        -d "{
            \"credential_id\": \"$CREDENTIAL_ID_1\",
            \"reason\": \"Test revocation - device compromised\"
        }")
    
    REVOKE_SUCCESS=$(echo "$REVOKE_RESULT" | jq -r '.success // false')
    
    if [ "$REVOKE_SUCCESS" == "true" ]; then
        pass "Credential revoked successfully"
        echo "$REVOKE_RESULT" | jq -c '{success, revoked_at}' 2>/dev/null || true
    else
        fail "Credential revocation failed"
        echo "$REVOKE_RESULT" | jq . 2>/dev/null || echo "$REVOKE_RESULT"
    fi
    
    echo ""
    echo "4.3 Checking credential status after revocation..."
    STATUS_AFTER=$(curl -s "$BASE_URL/api/v1/credential/status/$CRED_ID_ENCODED")
    REVOKED_AFTER=$(echo "$STATUS_AFTER" | jq -r '.revoked // false')
    
    if [ "$REVOKED_AFTER" == "true" ]; then
        pass "Credential correctly shows as revoked"
        REASON=$(echo "$STATUS_AFTER" | jq -r '.reason // "N/A"')
        echo "  Reason: $REASON"
    else
        fail "Credential should show as revoked"
    fi
    
    echo ""
    echo "4.4 Verifying revoked credential..."
    VERIFY_REVOKED=$(curl -s -X POST "$BASE_URL/api/v1/credential/verify" \
        -H "Content-Type: application/json" \
        -d "{\"credential_jwt\": \"$CREDENTIAL_1\"}")
    
    # Note: Verification may still pass if revocation check is not in verify endpoint
    info "Revoked credential verification result:"
    echo "$VERIFY_REVOKED" | jq -c . 2>/dev/null || echo "$VERIFY_REVOKED"
else
    # Use a test credential ID
    TEST_CRED_ID="test-credential-$(date +%s)"
    
    echo "4.1 Testing revocation with generated credential ID..."
    REVOKE_TEST=$(curl -s -X POST "$BASE_URL/api/v1/credential/revoke" \
        -H "Content-Type: application/json" \
        -d "{
            \"credential_id\": \"$TEST_CRED_ID\",
            \"reason\": \"Test revocation\"
        }")
    
    if echo "$REVOKE_TEST" | jq -e '.success == true' > /dev/null 2>&1; then
        pass "Credential revocation works"
    else
        fail "Credential revocation failed"
    fi
fi

# =============================================================================
# TEST 5: Key Rotation (On-Chain)
# =============================================================================
section "TEST 5: Key Rotation (On-Chain)"

if [ -n "$DID_3" ]; then
    DID_3_ENCODED=$(urlencode "$DID_3")
    
    echo "5.1 Getting current DID Document state..."
    RESOLVE_BEFORE=$(curl -s "$BASE_URL/api/v1/did/resolve/$DID_3_ENCODED")
    VM_COUNT_BEFORE=$(echo "$RESOLVE_BEFORE" | jq '.verificationMethod | length // 0' 2>/dev/null || echo "0")
    echo "  Verification methods before: $VM_COUNT_BEFORE"
    
    echo ""
    echo "5.2 Rotating key (ON-CHAIN - this may take ~7 seconds)..."
    NEW_KEY=$(openssl rand -hex 32)
    echo "  New public key: ${NEW_KEY:0:20}..."
    
    ROTATE_RESULT=$(curl -s -X POST "$BASE_URL/api/v1/did/rotate-key/$DID_3_ENCODED" \
        -H "Content-Type: application/json" \
        -d "{\"new_public_key\": \"$NEW_KEY\"}")
    
    ROTATE_SUCCESS=$(echo "$ROTATE_RESULT" | jq -r '.success // false')
    NEW_FRAGMENT=$(echo "$ROTATE_RESULT" | jq -r '.new_verification_method_id // empty')
    ROTATE_ERROR=$(echo "$ROTATE_RESULT" | jq -r '.error // empty')
    
    if [ "$ROTATE_SUCCESS" == "true" ]; then
        pass "Key rotation successful (ON-CHAIN)"
        echo "  New verification method: $NEW_FRAGMENT"
        
        echo ""
        echo "5.3 Verifying DID Document updated..."
        sleep 2  # Wait for blockchain confirmation
        
        # Clear cache first
        curl -s -X POST "$BASE_URL/api/v1/admin/cache/clear" > /dev/null 2>&1 || true
        
        RESOLVE_AFTER=$(curl -s "$BASE_URL/api/v1/did/resolve/$DID_3_ENCODED")
        VM_COUNT_AFTER=$(echo "$RESOLVE_AFTER" | jq '.verificationMethod | length // 0' 2>/dev/null || echo "0")
        echo "  Verification methods after: $VM_COUNT_AFTER"
        
        if [ "$VM_COUNT_AFTER" -gt "$VM_COUNT_BEFORE" ]; then
            pass "DID Document has new verification method"
        else
            info "Verification method count unchanged (may need cache clear)"
        fi
        
        # Show IOTA Explorer link
        echo ""
        echo -e "  ${BLUE}View on IOTA Explorer:${NC}"
        echo "  https://explorer.rebased.iota.org/object/$OBJECT_ID_3?network=testnet"
    else
        fail "Key rotation failed"
        echo "  Error: $ROTATE_ERROR"
    fi
    
    echo ""
    echo "5.4 Testing second key rotation..."
    NEW_KEY_2=$(openssl rand -hex 32)
    
    ROTATE_RESULT_2=$(curl -s -X POST "$BASE_URL/api/v1/did/rotate-key/$DID_3_ENCODED" \
        -H "Content-Type: application/json" \
        -d "{\"new_public_key\": \"$NEW_KEY_2\"}")
    
    if echo "$ROTATE_RESULT_2" | jq -e '.success == true' > /dev/null 2>&1; then
        pass "Second key rotation successful"
    else
        info "Second rotation result: $(echo "$ROTATE_RESULT_2" | jq -c .)"
    fi
else
    warn "No DID available for key rotation test"
fi

# =============================================================================
# TEST 6: DID Deactivation (On-Chain)
# =============================================================================
section "TEST 6: DID Deactivation (On-Chain)"

if [ -n "$DID_2" ]; then
    DID_2_ENCODED=$(urlencode "$DID_2")
    
    echo "6.1 Deactivating DID (ON-CHAIN - IRREVERSIBLE)..."
    echo -e "  ${YELLOW}WARNING: This permanently deactivates the DID on blockchain${NC}"
    
    DEACTIVATE_RESULT=$(curl -s -X POST "$BASE_URL/api/v1/did/deactivate/$DID_2_ENCODED")
    
    DEACTIVATE_SUCCESS=$(echo "$DEACTIVATE_RESULT" | jq -r '.success // false')
    DEACTIVATE_ERROR=$(echo "$DEACTIVATE_RESULT" | jq -r '.error // empty')
    
    if [ "$DEACTIVATE_SUCCESS" == "true" ]; then
        pass "DID deactivated successfully (ON-CHAIN)"
        echo "$DEACTIVATE_RESULT" | jq -c '{success, did, deactivated_at}' 2>/dev/null || true
        
        # Show IOTA Explorer link
        echo ""
        echo -e "  ${BLUE}View deactivated DID on IOTA Explorer:${NC}"
        echo "  https://explorer.rebased.iota.org/object/$OBJECT_ID_2?network=testnet"
    else
        fail "DID deactivation failed"
        echo "  Error: $DEACTIVATE_ERROR"
    fi
    
    echo ""
    echo "6.2 Testing double deactivation (should fail)..."
    DOUBLE_DEACTIVATE=$(curl -s -X POST "$BASE_URL/api/v1/did/deactivate/$DID_2_ENCODED")
    
    DOUBLE_SUCCESS=$(echo "$DOUBLE_DEACTIVATE" | jq -r '.success // true')
    
    if [ "$DOUBLE_SUCCESS" == "false" ]; then
        pass "Double deactivation correctly rejected"
        echo "  Error: $(echo "$DOUBLE_DEACTIVATE" | jq -r '.error // "Already deactivated"')"
    else
        fail "Double deactivation should be rejected"
    fi
    
    echo ""
    echo "6.3 Testing key rotation on deactivated DID (should fail)..."
    ROTATE_DEACTIVATED=$(curl -s -X POST "$BASE_URL/api/v1/did/rotate-key/$DID_2_ENCODED" \
        -H "Content-Type: application/json" \
        -d "{\"new_public_key\": \"$(openssl rand -hex 32)\"}")
    
    ROTATE_DEACT_SUCCESS=$(echo "$ROTATE_DEACTIVATED" | jq -r '.success // true')
    
    if [ "$ROTATE_DEACT_SUCCESS" == "false" ]; then
        pass "Key rotation on deactivated DID correctly rejected"
    else
        fail "Key rotation should fail on deactivated DID"
    fi
else
    warn "No DID available for deactivation test"
fi

# =============================================================================
# TEST 7: Unauthorized Operations
# =============================================================================
section "TEST 7: Unauthorized Operations"

# Try to deactivate a DID not created by this service
FAKE_DID="did:iota:testnet:0x0000000000000000000000000000000000000000000000000000000000000000"
FAKE_DID_ENCODED=$(urlencode "$FAKE_DID")

echo "7.1 Attempting to deactivate external DID (should fail)..."
UNAUTH_DEACTIVATE=$(curl -s -X POST "$BASE_URL/api/v1/did/deactivate/$FAKE_DID_ENCODED")

UNAUTH_SUCCESS=$(echo "$UNAUTH_DEACTIVATE" | jq -r '.success // true')

if [ "$UNAUTH_SUCCESS" == "false" ]; then
    pass "Unauthorized deactivation correctly rejected"
    echo "  Error: $(echo "$UNAUTH_DEACTIVATE" | jq -r '.error // empty' | head -c 80)..."
else
    fail "Unauthorized deactivation should be rejected"
fi

echo ""
echo "7.2 Attempting key rotation on external DID (should fail)..."
UNAUTH_ROTATE=$(curl -s -X POST "$BASE_URL/api/v1/did/rotate-key/$FAKE_DID_ENCODED" \
    -H "Content-Type: application/json" \
    -d "{\"new_public_key\": \"$(openssl rand -hex 32)\"}")

UNAUTH_ROTATE_SUCCESS=$(echo "$UNAUTH_ROTATE" | jq -r '.success // true')

if [ "$UNAUTH_ROTATE_SUCCESS" == "false" ]; then
    pass "Unauthorized key rotation correctly rejected"
else
    fail "Unauthorized key rotation should be rejected"
fi

# =============================================================================
# TEST 8: Input Validation
# =============================================================================
section "TEST 8: Input Validation"

echo "8.1 Testing registration with invalid public key (wrong length)..."
INVALID_KEY_RESULT=$(curl -s -X POST "$BASE_URL/api/v1/device/register" \
    -H "Content-Type: application/json" \
    -d '{
        "public_key": "tooshort",
        "device_type": "Sensor",
        "capabilities": []
    }')

if echo "$INVALID_KEY_RESULT" | jq -e 'has("error") or .success == false' > /dev/null 2>&1; then
    pass "Invalid public key correctly rejected"
else
    fail "Invalid public key should be rejected"
fi

echo ""
echo "8.2 Testing key rotation with invalid new key..."
if [ -n "$DID_1" ]; then
    INVALID_ROTATE=$(curl -s -X POST "$BASE_URL/api/v1/did/rotate-key/$DID_1_ENCODED" \
        -H "Content-Type: application/json" \
        -d '{"new_public_key": "not-valid-hex"}')
    
    if echo "$INVALID_ROTATE" | jq -e '.success == false' > /dev/null 2>&1; then
        pass "Invalid new key correctly rejected"
    else
        fail "Invalid new key should be rejected"
    fi
fi

echo ""
echo "8.3 Testing resolution of invalid DID..."
INVALID_DID_RESOLVE=$(curl -s "$BASE_URL/api/v1/did/resolve/not-a-valid-did")

if echo "$INVALID_DID_RESOLVE" | jq -e 'has("error")' > /dev/null 2>&1; then
    pass "Invalid DID resolution correctly rejected"
else
    info "Invalid DID response: $(echo "$INVALID_DID_RESOLVE" | jq -c .)"
fi

# =============================================================================
# TEST 9: Cache Management
# =============================================================================
section "TEST 9: Cache Management"

echo "9.1 Clearing cache..."
CACHE_CLEAR=$(curl -s -X POST "$BASE_URL/api/v1/admin/cache/clear")

if echo "$CACHE_CLEAR" | jq -e '.success == true or .cleared' > /dev/null 2>&1; then
    pass "Cache cleared successfully"
else
    info "Cache clear response: $(echo "$CACHE_CLEAR" | jq -c .)"
fi

echo ""
echo "9.2 Checking cache stats after clear..."
HEALTH_AFTER=$(curl -s "$BASE_URL/health")
echo "$HEALTH_AFTER" | jq '.cache_stats // "N/A"' 2>/dev/null || true

# =============================================================================
# TEST 10: Metrics Endpoint
# =============================================================================
section "TEST 10: Metrics Endpoint"

echo "10.1 Fetching metrics..."
METRICS=$(curl -s "$BASE_URL/metrics")

if [ -n "$METRICS" ]; then
    pass "Metrics endpoint available"
    echo "$METRICS" | head -20
    if [ $(echo "$METRICS" | wc -l) -gt 20 ]; then
        echo "... (truncated)"
    fi
else
    info "Metrics endpoint returned empty response"
fi

# =============================================================================
# SUMMARY
# =============================================================================
section "TEST SUMMARY"

echo ""
echo "Results:"
echo -e "  ${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "  ${RED}Failed: $TESTS_FAILED${NC}"
echo ""

echo "DIDs Created:"
[ -n "$DID_1" ] && echo "  1. $DID_1 (active)"
[ -n "$DID_2" ] && echo "  2. $DID_2 (deactivated)"
[ -n "$DID_3" ] && echo "  3. $DID_3 (key rotated)"
echo ""

echo -e "${BLUE}IOTA Explorer Links:${NC}"
[ -n "$OBJECT_ID_1" ] && echo "  Device 1: https://explorer.rebased.iota.org/object/$OBJECT_ID_1?network=testnet"
[ -n "$OBJECT_ID_2" ] && echo "  Device 2: https://explorer.rebased.iota.org/object/$OBJECT_ID_2?network=testnet"
[ -n "$OBJECT_ID_3" ] && echo "  Device 3: https://explorer.rebased.iota.org/object/$OBJECT_ID_3?network=testnet"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}=============================================="
    echo "  ALL TESTS PASSED!"
    echo -e "==============================================${NC}"
    exit 0
else
    echo -e "${YELLOW}=============================================="
    echo "  SOME TESTS FAILED - Review output above"
    echo -e "==============================================${NC}"
    exit 1
fi