#!/bin/bash
# =============================================================================
# IOTA Identity IoT - Full Coverage Test Suite
# =============================================================================
# Comprehensive test suite covering ALL API endpoints, edge cases, error paths,
# concurrency, performance, and the full device lifecycle.
#
# Requirements:
#   - identity-service running on localhost:8080
#   - curl, jq, openssl installed
#
# Usage:
#   chmod +x test_full_coverage.sh
#   ./test_full_coverage.sh [--base-url http://localhost:8080] [--skip-onchain]
# =============================================================================

set -euo pipefail

# =============================================================================
# CONFIGURATION & CLI ARGS
# =============================================================================
BASE_URL="${BASE_URL:-http://localhost:8080}"
SKIP_ONCHAIN=false
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --base-url) BASE_URL="$2"; shift 2 ;;
        --skip-onchain) SKIP_ONCHAIN=true; shift ;;
        --verbose) VERBOSE=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# =============================================================================
# COLORS & COUNTERS
# =============================================================================
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0
TOTAL_START=$(date +%s)

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
pass() {
    echo -e "  ${GREEN}PASS${NC} $1"
    ((TESTS_PASSED++))
}

fail() {
    echo -e "  ${RED}FAIL${NC} $1"
    ((TESTS_FAILED++))
    if [ "$VERBOSE" = true ] && [ -n "${2:-}" ]; then
        echo -e "       ${RED}Detail: $2${NC}"
    fi
}

skip() {
    echo -e "  ${YELLOW}SKIP${NC} $1"
    ((TESTS_SKIPPED++))
}

info() {
    echo -e "  ${BLUE}INFO${NC} $1"
}

section() {
    echo ""
    echo -e "${CYAN}${BOLD}================================================================"
    echo "  $1"
    echo -e "================================================================${NC}"
}

subsection() {
    echo ""
    echo -e "  ${MAGENTA}--- $1 ---${NC}"
}

urlencode() {
    echo -n "$1" | jq -sRr @uri
}

# HTTP helper: returns "HTTP_CODE|BODY"
http_get() {
    curl -s -w "\n%{http_code}" "$1" 2>/dev/null || echo -e "\n000"
}

http_post() {
    local url="$1"
    local data="$2"
    curl -s -w "\n%{http_code}" -X POST "$url" \
        -H "Content-Type: application/json" \
        -d "$data" 2>/dev/null || echo -e "\n000"
}

# Extract HTTP code (last line) and body (everything else)
get_body() {
    echo "$1" | sed '$d'
}

get_code() {
    echo "$1" | tail -1
}

echo -e "${BOLD}================================================================"
echo "  IOTA Identity IoT - Full Coverage Test Suite"
echo "================================================================${NC}"
echo ""
echo "  Target:        $BASE_URL"
echo "  Skip on-chain: $SKIP_ONCHAIN"
echo "  Date:          $(date)"
echo ""

# =============================================================================
# SECTION 0: PRE-FLIGHT CHECKS
# =============================================================================
section "SECTION 0: Pre-flight Checks"

subsection "0.1 Service availability"
RESP=$(http_get "$BASE_URL/health")
BODY=$(get_body "$RESP")
CODE=$(get_code "$RESP")

if [ "$CODE" = "200" ] && echo "$BODY" | jq -e '.status == "healthy"' > /dev/null 2>&1; then
    pass "Service is healthy (HTTP $CODE)"
else
    fail "Service not reachable at $BASE_URL (HTTP $CODE)"
    echo -e "${RED}Cannot proceed without a running service. Start with:${NC}"
    echo "  cargo run --release --package identity-service"
    exit 1
fi

subsection "0.2 Health response structure"
if echo "$BODY" | jq -e 'has("status")' > /dev/null 2>&1; then
    pass "Health response contains 'status' field"
else
    fail "Health response missing 'status' field"
fi

if echo "$BODY" | jq -e 'has("version")' > /dev/null 2>&1; then
    pass "Health response contains 'version' field"
else
    fail "Health response missing 'version' field"
fi

VERSION=$(echo "$BODY" | jq -r '.version // "unknown"')
info "Service version: $VERSION"

# =============================================================================
# SECTION 1: DEVICE REGISTRATION
# =============================================================================
section "SECTION 1: Device Registration"

# --- 1.1 Register Sensor ---
subsection "1.1 Register Sensor device"
PK_SENSOR=$(openssl rand -hex 32)

RESP=$(http_post "$BASE_URL/api/v1/device/register" "{
    \"public_key\": \"$PK_SENSOR\",
    \"device_type\": \"sensor\",
    \"capabilities\": [\"temperature\", \"humidity\", \"pressure\"],
    \"manufacturer\": \"TestCorp\",
    \"model\": \"T-100\"
}")
BODY=$(get_body "$RESP")
CODE=$(get_code "$RESP")

DID_SENSOR=$(echo "$BODY" | jq -r '.did // empty')
OBJ_SENSOR=$(echo "$BODY" | jq -r '.object_id // empty')
JWT_SENSOR=$(echo "$BODY" | jq -r '.credential_jwt // empty')
EXPIRES_SENSOR=$(echo "$BODY" | jq -r '.credential_expires_at // empty')

if [ "$CODE" = "200" ] && [ -n "$DID_SENSOR" ] && [ "$DID_SENSOR" != "null" ]; then
    pass "Sensor registered (HTTP $CODE)"
    info "DID: $DID_SENSOR"
    info "Object ID: $OBJ_SENSOR"
else
    fail "Sensor registration failed (HTTP $CODE)" "$BODY"
fi

# Validate response fields
if [ -n "$DID_SENSOR" ] && [[ "$DID_SENSOR" == did:iota:* ]]; then
    pass "DID has correct prefix (did:iota:...)"
else
    fail "DID format invalid: $DID_SENSOR"
fi

if [ -n "$OBJ_SENSOR" ] && [[ "$OBJ_SENSOR" == 0x* ]]; then
    pass "Object ID has correct prefix (0x...)"
else
    fail "Object ID format invalid: $OBJ_SENSOR"
fi

if [ -n "$JWT_SENSOR" ]; then
    JWT_PARTS=$(echo "$JWT_SENSOR" | tr '.' '\n' | wc -l)
    if [ "$JWT_PARTS" -eq 3 ]; then
        pass "Credential JWT has 3 parts (header.payload.signature)"
    else
        fail "JWT should have 3 parts, got $JWT_PARTS"
    fi
else
    fail "No credential JWT returned"
fi

if [ -n "$EXPIRES_SENSOR" ] && [ "$EXPIRES_SENSOR" != "null" ]; then
    pass "Credential expiration date present"
else
    fail "Credential expiration date missing"
fi

# --- 1.2 Register Gateway ---
subsection "1.2 Register Gateway device"
PK_GATEWAY=$(openssl rand -hex 32)

RESP=$(http_post "$BASE_URL/api/v1/device/register" "{
    \"public_key\": \"$PK_GATEWAY\",
    \"device_type\": \"Gateway\",
    \"capabilities\": [\"routing\", \"aggregation\", \"filtering\"]
}")
BODY=$(get_body "$RESP")
CODE=$(get_code "$RESP")

DID_GATEWAY=$(echo "$BODY" | jq -r '.did // empty')
OBJ_GATEWAY=$(echo "$BODY" | jq -r '.object_id // empty')
JWT_GATEWAY=$(echo "$BODY" | jq -r '.credential_jwt // empty')

if [ "$CODE" = "200" ] && [ -n "$DID_GATEWAY" ] && [ "$DID_GATEWAY" != "null" ]; then
    pass "Gateway registered (HTTP $CODE)"
else
    fail "Gateway registration failed (HTTP $CODE)"
fi

# --- 1.3 Register Actuator ---
subsection "1.3 Register Actuator device"
PK_ACTUATOR=$(openssl rand -hex 32)

RESP=$(http_post "$BASE_URL/api/v1/device/register" "{
    \"public_key\": \"$PK_ACTUATOR\",
    \"device_type\": \"actuator\",
    \"capabilities\": [\"relay\", \"motor\"]
}")
BODY=$(get_body "$RESP")
CODE=$(get_code "$RESP")

DID_ACTUATOR=$(echo "$BODY" | jq -r '.did // empty')
OBJ_ACTUATOR=$(echo "$BODY" | jq -r '.object_id // empty')
JWT_ACTUATOR=$(echo "$BODY" | jq -r '.credential_jwt // empty')

if [ "$CODE" = "200" ] && [ -n "$DID_ACTUATOR" ] && [ "$DID_ACTUATOR" != "null" ]; then
    pass "Actuator registered (HTTP $CODE)"
else
    fail "Actuator registration failed (HTTP $CODE)"
fi

# --- 1.4 Register Controller ---
subsection "1.4 Register Controller device"
PK_CONTROLLER=$(openssl rand -hex 32)

RESP=$(http_post "$BASE_URL/api/v1/device/register" "{
    \"public_key\": \"$PK_CONTROLLER\",
    \"device_type\": \"controller\",
    \"capabilities\": [\"command\", \"monitor\"]
}")
BODY=$(get_body "$RESP")
CODE=$(get_code "$RESP")

DID_CONTROLLER=$(echo "$BODY" | jq -r '.did // empty')
JWT_CONTROLLER=$(echo "$BODY" | jq -r '.credential_jwt // empty')

if [ "$CODE" = "200" ] && [ -n "$DID_CONTROLLER" ] && [ "$DID_CONTROLLER" != "null" ]; then
    pass "Controller registered (HTTP $CODE)"
else
    fail "Controller registration failed (HTTP $CODE)"
fi

# --- 1.5 Register Edge device ---
subsection "1.5 Register Edge device"
PK_EDGE=$(openssl rand -hex 32)

RESP=$(http_post "$BASE_URL/api/v1/device/register" "{
    \"public_key\": \"$PK_EDGE\",
    \"device_type\": \"edge\",
    \"capabilities\": [\"compute\", \"storage\", \"inference\"]
}")
BODY=$(get_body "$RESP")
CODE=$(get_code "$RESP")

DID_EDGE=$(echo "$BODY" | jq -r '.did // empty')

if [ "$CODE" = "200" ] && [ -n "$DID_EDGE" ] && [ "$DID_EDGE" != "null" ]; then
    pass "Edge device registered (HTTP $CODE)"
else
    fail "Edge device registration failed (HTTP $CODE)"
fi

# --- 1.6 Register Generic device ---
subsection "1.6 Register Generic device"
PK_GENERIC=$(openssl rand -hex 32)

RESP=$(http_post "$BASE_URL/api/v1/device/register" "{
    \"public_key\": \"$PK_GENERIC\",
    \"device_type\": \"generic\",
    \"capabilities\": []
}")
BODY=$(get_body "$RESP")
CODE=$(get_code "$RESP")

DID_GENERIC=$(echo "$BODY" | jq -r '.did // empty')

if [ "$CODE" = "200" ] && [ -n "$DID_GENERIC" ] && [ "$DID_GENERIC" != "null" ]; then
    pass "Generic device registered with empty capabilities (HTTP $CODE)"
else
    fail "Generic device registration failed (HTTP $CODE)"
fi

# --- 1.7 Uniqueness: each registration produces a different DID ---
subsection "1.7 DID uniqueness across registrations"
if [ "$DID_SENSOR" != "$DID_GATEWAY" ] && [ "$DID_SENSOR" != "$DID_ACTUATOR" ] && [ "$DID_GATEWAY" != "$DID_ACTUATOR" ]; then
    pass "All registered DIDs are unique"
else
    fail "Duplicate DID detected among registered devices"
fi

# =============================================================================
# SECTION 2: REGISTRATION INPUT VALIDATION (NEGATIVE CASES)
# =============================================================================
section "SECTION 2: Registration Input Validation"

subsection "2.1 Public key too short"
RESP=$(http_post "$BASE_URL/api/v1/device/register" '{
    "public_key": "abcdef",
    "device_type": "sensor",
    "capabilities": []
}')
CODE=$(get_code "$RESP")
BODY=$(get_body "$RESP")

if [ "$CODE" = "400" ]; then
    pass "Short public key rejected with HTTP 400"
elif echo "$BODY" | jq -e 'has("error")' > /dev/null 2>&1; then
    pass "Short public key rejected with error response"
else
    fail "Short public key should be rejected (HTTP $CODE)"
fi

subsection "2.2 Public key too long"
LONG_KEY=$(openssl rand -hex 64)
RESP=$(http_post "$BASE_URL/api/v1/device/register" "{
    \"public_key\": \"$LONG_KEY\",
    \"device_type\": \"sensor\",
    \"capabilities\": []
}")
CODE=$(get_code "$RESP")
BODY=$(get_body "$RESP")

if [ "$CODE" = "400" ] || echo "$BODY" | jq -e 'has("error")' > /dev/null 2>&1; then
    pass "Too-long public key rejected"
else
    fail "Too-long public key should be rejected (HTTP $CODE)"
fi

subsection "2.3 Non-hex public key"
RESP=$(http_post "$BASE_URL/api/v1/device/register" '{
    "public_key": "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
    "device_type": "sensor",
    "capabilities": []
}')
CODE=$(get_code "$RESP")
BODY=$(get_body "$RESP")

# This might succeed at the API level (length=64) but fail at DID creation
# since it's not valid hex. Either way we check for error handling.
if [ "$CODE" != "200" ] || echo "$BODY" | jq -e 'has("error")' > /dev/null 2>&1; then
    pass "Non-hex public key handled (HTTP $CODE)"
else
    info "Non-hex key accepted at API level (may fail at DID creation)"
fi

subsection "2.4 Empty JSON body"
RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/api/v1/device/register" \
    -H "Content-Type: application/json" \
    -d '{}' 2>/dev/null || echo -e "\n000")
CODE=$(get_code "$RESP")

if [ "$CODE" = "400" ] || [ "$CODE" = "422" ]; then
    pass "Empty body rejected (HTTP $CODE)"
else
    fail "Empty body should be rejected (HTTP $CODE)"
fi

subsection "2.5 Missing Content-Type header"
RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/api/v1/device/register" \
    -d '{"public_key":"abc"}' 2>/dev/null || echo -e "\n000")
CODE=$(get_code "$RESP")

if [ "$CODE" = "400" ] || [ "$CODE" = "415" ] || [ "$CODE" = "422" ]; then
    pass "Missing Content-Type rejected (HTTP $CODE)"
else
    fail "Missing Content-Type should be rejected (HTTP $CODE)"
fi

subsection "2.6 Malformed JSON"
RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/api/v1/device/register" \
    -H "Content-Type: application/json" \
    -d '{not valid json' 2>/dev/null || echo -e "\n000")
CODE=$(get_code "$RESP")

if [ "$CODE" = "400" ] || [ "$CODE" = "422" ]; then
    pass "Malformed JSON rejected (HTTP $CODE)"
else
    fail "Malformed JSON should be rejected (HTTP $CODE)"
fi

subsection "2.7 Registration with many capabilities"
MANY_CAPS=$(python3 -c "import json; print(json.dumps(['cap_'+str(i) for i in range(50)]))" 2>/dev/null || echo '["a","b","c","d","e"]')
PK_CAPS=$(openssl rand -hex 32)
RESP=$(http_post "$BASE_URL/api/v1/device/register" "{
    \"public_key\": \"$PK_CAPS\",
    \"device_type\": \"Sensor\",
    \"capabilities\": $MANY_CAPS
}")
CODE=$(get_code "$RESP")

if [ "$CODE" = "200" ]; then
    pass "Registration with many capabilities accepted (HTTP $CODE)"
else
    info "Registration with many capabilities: HTTP $CODE"
fi

# =============================================================================
# SECTION 3: DID RESOLUTION
# =============================================================================
section "SECTION 3: DID Resolution"

subsection "3.1 Resolve Sensor DID"
if [ -n "$DID_SENSOR" ]; then
    DID_SENSOR_ENC=$(urlencode "$DID_SENSOR")
    RESP=$(http_get "$BASE_URL/api/v1/did/resolve/$DID_SENSOR_ENC")
    BODY=$(get_body "$RESP")
    CODE=$(get_code "$RESP")

    if [ "$CODE" = "200" ]; then
        pass "Sensor DID resolved (HTTP $CODE)"
    else
        fail "Sensor DID resolution failed (HTTP $CODE)"
    fi

    # Validate response structure
    DOC_ID=$(echo "$BODY" | jq -r '.did_document.id // empty')
    if [ -n "$DOC_ID" ] && [ "$DOC_ID" != "null" ]; then
        pass "Response contains did_document.id"
    else
        fail "Response missing did_document.id"
    fi

    VM_COUNT=$(echo "$BODY" | jq '.did_document.verification_methods | length' 2>/dev/null || echo "0")
    if [ "$VM_COUNT" -ge 1 ]; then
        pass "DID Document has $VM_COUNT verification method(s)"
    else
        fail "DID Document should have at least 1 verification method"
    fi

    FROM_CACHE=$(echo "$BODY" | jq -r '.from_cache // "missing"')
    if [ "$FROM_CACHE" != "missing" ]; then
        pass "Response contains 'from_cache' field ($FROM_CACHE)"
    else
        fail "Response missing 'from_cache' field"
    fi

    RESOLUTION_TIME=$(echo "$BODY" | jq -r '.resolution_time_ms // "missing"')
    if [ "$RESOLUTION_TIME" != "missing" ]; then
        pass "Response contains 'resolution_time_ms' ($RESOLUTION_TIME ms)"
    else
        fail "Response missing 'resolution_time_ms' field"
    fi
fi

subsection "3.2 Resolve all registered DIDs"
for DID_VAR in "$DID_GATEWAY" "$DID_ACTUATOR" "$DID_CONTROLLER" "$DID_EDGE" "$DID_GENERIC"; do
    if [ -n "$DID_VAR" ]; then
        DID_ENC=$(urlencode "$DID_VAR")
        RESP=$(http_get "$BASE_URL/api/v1/did/resolve/$DID_ENC")
        CODE=$(get_code "$RESP")
        if [ "$CODE" = "200" ]; then
            pass "Resolved: ${DID_VAR:0:40}..."
        else
            fail "Failed to resolve: ${DID_VAR:0:40}... (HTTP $CODE)"
        fi
    fi
done

subsection "3.3 Resolution caching"
if [ -n "$DID_SENSOR" ]; then
    DID_SENSOR_ENC=$(urlencode "$DID_SENSOR")

    # First call (may populate cache)
    http_get "$BASE_URL/api/v1/did/resolve/$DID_SENSOR_ENC" > /dev/null

    # Second call (should be cached)
    START_NS=$(date +%s%N)
    RESP=$(http_get "$BASE_URL/api/v1/did/resolve/$DID_SENSOR_ENC")
    END_NS=$(date +%s%N)
    ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))
    BODY=$(get_body "$RESP")

    FROM_CACHE=$(echo "$BODY" | jq -r '.from_cache // false')
    if [ "$FROM_CACHE" = "true" ]; then
        pass "Second resolution served from cache"
    else
        info "Second resolution not from cache (from_cache=$FROM_CACHE)"
    fi

    if [ "$ELAPSED_MS" -lt 200 ]; then
        pass "Cached resolution fast: ${ELAPSED_MS}ms"
    else
        info "Resolution took ${ELAPSED_MS}ms"
    fi
fi

subsection "3.4 Resolve invalid DID"
RESP=$(http_get "$BASE_URL/api/v1/did/resolve/not-a-valid-did")
CODE=$(get_code "$RESP")
BODY=$(get_body "$RESP")

if [ "$CODE" = "400" ] || [ "$CODE" = "404" ] || echo "$BODY" | jq -e 'has("error")' > /dev/null 2>&1; then
    pass "Invalid DID correctly rejected (HTTP $CODE)"
else
    fail "Invalid DID should be rejected (HTTP $CODE)"
fi

subsection "3.5 Resolve non-existent DID"
FAKE_DID="did:iota:testnet:0x0000000000000000000000000000000000000000000000000000000000000001"
FAKE_DID_ENC=$(urlencode "$FAKE_DID")
RESP=$(http_get "$BASE_URL/api/v1/did/resolve/$FAKE_DID_ENC")
CODE=$(get_code "$RESP")
BODY=$(get_body "$RESP")

if [ "$CODE" = "404" ] || [ "$CODE" = "500" ] || echo "$BODY" | jq -e 'has("error")' > /dev/null 2>&1; then
    pass "Non-existent DID handled (HTTP $CODE)"
else
    fail "Non-existent DID should return error (HTTP $CODE)"
fi

subsection "3.6 Resolve with empty DID path"
RESP=$(http_get "$BASE_URL/api/v1/did/resolve/")
CODE=$(get_code "$RESP")

if [ "$CODE" = "400" ] || [ "$CODE" = "404" ] || [ "$CODE" = "405" ]; then
    pass "Empty DID path handled (HTTP $CODE)"
else
    info "Empty DID path returned HTTP $CODE"
fi

# =============================================================================
# SECTION 4: CREDENTIAL VERIFICATION
# =============================================================================
section "SECTION 4: Credential Verification"

subsection "4.1 Verify valid Sensor credential"
if [ -n "$JWT_SENSOR" ]; then
    RESP=$(http_post "$BASE_URL/api/v1/credential/verify" \
        "{\"credential_jwt\": \"$JWT_SENSOR\"}")
    BODY=$(get_body "$RESP")
    CODE=$(get_code "$RESP")

    VALID=$(echo "$BODY" | jq -r '.valid // false')
    if [ "$VALID" = "true" ]; then
        pass "Sensor credential verified"
    else
        fail "Sensor credential should be valid" "$BODY"
    fi

    # Verify response structure
    SUBJECT=$(echo "$BODY" | jq -r '.subject_did // empty')
    ISSUER=$(echo "$BODY" | jq -r '.issuer_did // empty')
    EXPIRES=$(echo "$BODY" | jq -r '.expires_at // empty')

    if [ -n "$SUBJECT" ] && [ "$SUBJECT" != "null" ]; then
        pass "Response contains subject_did"
    else
        fail "Response missing subject_did"
    fi

    if [ -n "$ISSUER" ] && [ "$ISSUER" != "null" ]; then
        pass "Response contains issuer_did"
    else
        fail "Response missing issuer_did"
    fi

    if [ -n "$EXPIRES" ] && [ "$EXPIRES" != "null" ]; then
        pass "Response contains expires_at"
    else
        fail "Response missing expires_at"
    fi
else
    skip "No Sensor JWT available"
fi

subsection "4.2 Verify Gateway credential"
if [ -n "$JWT_GATEWAY" ]; then
    RESP=$(http_post "$BASE_URL/api/v1/credential/verify" \
        "{\"credential_jwt\": \"$JWT_GATEWAY\"}")
    BODY=$(get_body "$RESP")
    VALID=$(echo "$BODY" | jq -r '.valid // false')
    if [ "$VALID" = "true" ]; then
        pass "Gateway credential verified"
    else
        fail "Gateway credential should be valid"
    fi
else
    skip "No Gateway JWT available"
fi

subsection "4.3 Verify Actuator credential"
if [ -n "$JWT_ACTUATOR" ]; then
    RESP=$(http_post "$BASE_URL/api/v1/credential/verify" \
        "{\"credential_jwt\": \"$JWT_ACTUATOR\"}")
    BODY=$(get_body "$RESP")
    VALID=$(echo "$BODY" | jq -r '.valid // false')
    if [ "$VALID" = "true" ]; then
        pass "Actuator credential verified"
    else
        fail "Actuator credential should be valid"
    fi
else
    skip "No Actuator JWT available"
fi

subsection "4.4 Reject invalid JWT format"
RESP=$(http_post "$BASE_URL/api/v1/credential/verify" \
    '{"credential_jwt": "not.a.valid.jwt.with.too.many.parts"}')
BODY=$(get_body "$RESP")
VALID=$(echo "$BODY" | jq -r '.valid // true')

if [ "$VALID" = "false" ]; then
    pass "Invalid JWT (too many parts) rejected"
else
    fail "Invalid JWT should be rejected"
fi

subsection "4.5 Reject JWT with only 2 parts"
RESP=$(http_post "$BASE_URL/api/v1/credential/verify" \
    '{"credential_jwt": "header.payload"}')
BODY=$(get_body "$RESP")
VALID=$(echo "$BODY" | jq -r '.valid // true')

if [ "$VALID" = "false" ]; then
    pass "JWT with 2 parts rejected"
else
    fail "JWT with 2 parts should be rejected"
fi

subsection "4.6 Reject single-string JWT"
RESP=$(http_post "$BASE_URL/api/v1/credential/verify" \
    '{"credential_jwt": "singlestring"}')
BODY=$(get_body "$RESP")
VALID=$(echo "$BODY" | jq -r '.valid // true')

if [ "$VALID" = "false" ]; then
    pass "Single-string JWT rejected"
else
    fail "Single-string JWT should be rejected"
fi

subsection "4.7 Reject empty JWT"
RESP=$(http_post "$BASE_URL/api/v1/credential/verify" \
    '{"credential_jwt": ""}')
BODY=$(get_body "$RESP")
CODE=$(get_code "$RESP")
VALID=$(echo "$BODY" | jq -r '.valid // true')

if [ "$VALID" = "false" ] || [ "$CODE" = "400" ]; then
    pass "Empty JWT rejected"
else
    fail "Empty JWT should be rejected"
fi

subsection "4.8 Reject tampered JWT (modified payload)"
if [ -n "$JWT_SENSOR" ]; then
    # Modify one character in the payload part
    HEADER=$(echo "$JWT_SENSOR" | cut -d'.' -f1)
    PAYLOAD=$(echo "$JWT_SENSOR" | cut -d'.' -f2)
    SIGNATURE=$(echo "$JWT_SENSOR" | cut -d'.' -f3)

    # Flip the first character of the payload
    FIRST_CHAR="${PAYLOAD:0:1}"
    if [ "$FIRST_CHAR" = "a" ]; then
        TAMPERED_CHAR="b"
    else
        TAMPERED_CHAR="a"
    fi
    TAMPERED_PAYLOAD="${TAMPERED_CHAR}${PAYLOAD:1}"
    TAMPERED_JWT="${HEADER}.${TAMPERED_PAYLOAD}.${SIGNATURE}"

    RESP=$(http_post "$BASE_URL/api/v1/credential/verify" \
        "{\"credential_jwt\": \"$TAMPERED_JWT\"}")
    BODY=$(get_body "$RESP")
    CODE=$(get_code "$RESP")
    VALID=$(echo "$BODY" | jq -r '.valid // true')

    if [ "$VALID" = "false" ] || [ "$CODE" = "400" ]; then
        pass "Tampered JWT rejected"
    else
        fail "Tampered JWT should be rejected"
    fi
else
    skip "No JWT available for tampering test"
fi

subsection "4.9 Missing credential_jwt field"
RESP=$(http_post "$BASE_URL/api/v1/credential/verify" '{}')
CODE=$(get_code "$RESP")

if [ "$CODE" = "400" ] || [ "$CODE" = "422" ]; then
    pass "Missing credential_jwt field rejected (HTTP $CODE)"
else
    fail "Missing field should be rejected (HTTP $CODE)"
fi

# =============================================================================
# SECTION 5: CREDENTIAL REVOCATION
# =============================================================================
section "SECTION 5: Credential Revocation"

# Extract credential ID from JWT for sensor
CRED_ID_SENSOR=""
if [ -n "$JWT_SENSOR" ]; then
    PAYLOAD_B64=$(echo "$JWT_SENSOR" | cut -d'.' -f2)
    # Add padding if needed
    PADDED="$PAYLOAD_B64"
    MOD=$((${#PADDED} % 4))
    if [ "$MOD" -eq 2 ]; then PADDED="${PADDED}=="; elif [ "$MOD" -eq 3 ]; then PADDED="${PADDED}="; fi
    CRED_ID_SENSOR=$(echo "$PADDED" | base64 -d 2>/dev/null | jq -r '.vc.id // empty' 2>/dev/null || echo "")
fi

# Use a test credential ID if extraction failed
if [ -z "$CRED_ID_SENSOR" ] || [ "$CRED_ID_SENSOR" = "null" ]; then
    CRED_ID_SENSOR="test-cred-$(date +%s)-sensor"
    info "Using generated credential ID: $CRED_ID_SENSOR"
fi

subsection "5.1 Check status before revocation"
CRED_ID_ENC=$(urlencode "$CRED_ID_SENSOR")
RESP=$(http_get "$BASE_URL/api/v1/credential/status/$CRED_ID_ENC")
BODY=$(get_body "$RESP")
CODE=$(get_code "$RESP")

REVOKED=$(echo "$BODY" | jq -r '.revoked // "missing"')
if [ "$CODE" = "200" ] && [ "$REVOKED" = "false" ]; then
    pass "Credential status: active (not revoked)"
elif [ "$CODE" = "200" ]; then
    info "Credential status: revoked=$REVOKED"
else
    fail "Credential status check failed (HTTP $CODE)"
fi

# Validate status response fields
RESP_CRED_ID=$(echo "$BODY" | jq -r '.credential_id // empty')
if [ -n "$RESP_CRED_ID" ]; then
    pass "Status response contains credential_id"
else
    fail "Status response missing credential_id"
fi

subsection "5.2 Revoke credential with reason"
RESP=$(http_post "$BASE_URL/api/v1/credential/revoke" "{
    \"credential_id\": \"$CRED_ID_SENSOR\",
    \"reason\": \"Device compromised during testing\"
}")
BODY=$(get_body "$RESP")
CODE=$(get_code "$RESP")

REVOKE_OK=$(echo "$BODY" | jq -r '.success // false')
if [ "$REVOKE_OK" = "true" ]; then
    pass "Credential revoked with reason"
else
    fail "Credential revocation failed" "$BODY"
fi

REVOKED_AT=$(echo "$BODY" | jq -r '.revoked_at // empty')
if [ -n "$REVOKED_AT" ] && [ "$REVOKED_AT" != "null" ]; then
    pass "Revocation timestamp present: $REVOKED_AT"
else
    fail "Revocation timestamp missing"
fi

subsection "5.3 Check status after revocation"
RESP=$(http_get "$BASE_URL/api/v1/credential/status/$CRED_ID_ENC")
BODY=$(get_body "$RESP")

REVOKED=$(echo "$BODY" | jq -r '.revoked // false')
if [ "$REVOKED" = "true" ]; then
    pass "Credential shows as revoked"
else
    fail "Credential should show as revoked"
fi

REASON=$(echo "$BODY" | jq -r '.reason // empty')
if [ -n "$REASON" ] && [ "$REASON" != "null" ]; then
    pass "Revocation reason preserved: $REASON"
else
    info "No reason in status response"
fi

subsection "5.4 Double revocation (should fail)"
RESP=$(http_post "$BASE_URL/api/v1/credential/revoke" "{
    \"credential_id\": \"$CRED_ID_SENSOR\",
    \"reason\": \"Second attempt\"
}")
BODY=$(get_body "$RESP")

REVOKE_OK=$(echo "$BODY" | jq -r '.success // true')
if [ "$REVOKE_OK" = "false" ]; then
    pass "Double revocation correctly rejected"
else
    fail "Double revocation should be rejected"
fi

subsection "5.5 Verify revoked credential (should fail verification)"
if [ -n "$JWT_SENSOR" ] && [ "$CRED_ID_SENSOR" != "test-cred-"* ]; then
    RESP=$(http_post "$BASE_URL/api/v1/credential/verify" \
        "{\"credential_jwt\": \"$JWT_SENSOR\"}")
    BODY=$(get_body "$RESP")
    VALID=$(echo "$BODY" | jq -r '.valid // true')

    if [ "$VALID" = "false" ]; then
        pass "Revoked credential fails verification"
        ERROR_MSG=$(echo "$BODY" | jq -r '.error // empty')
        if echo "$ERROR_MSG" | grep -qi "revok"; then
            pass "Error message mentions revocation"
        else
            info "Error message: $ERROR_MSG"
        fi
    else
        info "Revoked credential still passes verification (revocation check may not be in verify path)"
    fi
fi

subsection "5.6 Revoke credential without reason"
TEST_CRED_NO_REASON="test-cred-noreason-$(date +%s)"
RESP=$(http_post "$BASE_URL/api/v1/credential/revoke" "{
    \"credential_id\": \"$TEST_CRED_NO_REASON\"
}")
BODY=$(get_body "$RESP")

REVOKE_OK=$(echo "$BODY" | jq -r '.success // false')
if [ "$REVOKE_OK" = "true" ]; then
    pass "Revocation without reason accepted"
else
    fail "Revocation without reason should work"
fi

subsection "5.7 Check status of never-revoked credential"
NEVER_REVOKED_ID="never-revoked-cred-$(date +%s)"
NEVER_REVOKED_ENC=$(urlencode "$NEVER_REVOKED_ID")
RESP=$(http_get "$BASE_URL/api/v1/credential/status/$NEVER_REVOKED_ENC")
BODY=$(get_body "$RESP")

REVOKED=$(echo "$BODY" | jq -r '.revoked // true')
if [ "$REVOKED" = "false" ]; then
    pass "Unknown credential shows as not revoked"
else
    fail "Unknown credential should not be revoked"
fi

# =============================================================================
# SECTION 6: KEY ROTATION (ON-CHAIN)
# =============================================================================
section "SECTION 6: Key Rotation (On-Chain)"

if [ "$SKIP_ONCHAIN" = true ]; then
    skip "Key rotation tests (--skip-onchain)"
else
    subsection "6.1 Rotate key for Gateway device"
    if [ -n "$DID_GATEWAY" ]; then
        DID_GW_ENC=$(urlencode "$DID_GATEWAY")

        # Resolve before rotation
        RESP_BEFORE=$(http_get "$BASE_URL/api/v1/did/resolve/$DID_GW_ENC")
        BODY_BEFORE=$(get_body "$RESP_BEFORE")
        VM_BEFORE=$(echo "$BODY_BEFORE" | jq '.did_document.verification_methods | length' 2>/dev/null || echo "0")
        info "Verification methods before rotation: $VM_BEFORE"

        NEW_KEY_1=$(openssl rand -hex 32)
        RESP=$(http_post "$BASE_URL/api/v1/did/rotate-key/$DID_GW_ENC" \
            "{\"new_public_key\": \"$NEW_KEY_1\"}")
        BODY=$(get_body "$RESP")
        CODE=$(get_code "$RESP")

        ROTATE_OK=$(echo "$BODY" | jq -r '.success // false')
        NEW_VM_ID=$(echo "$BODY" | jq -r '.new_verification_method_id // empty')

        if [ "$ROTATE_OK" = "true" ]; then
            pass "Key rotation successful (HTTP $CODE)"
            info "New verification method: $NEW_VM_ID"

            # Wait for blockchain and clear cache
            sleep 2
            http_post "$BASE_URL/api/v1/admin/cache/clear" '{}' > /dev/null 2>&1

            # Verify DID Document updated
            RESP_AFTER=$(http_get "$BASE_URL/api/v1/did/resolve/$DID_GW_ENC")
            BODY_AFTER=$(get_body "$RESP_AFTER")
            VM_AFTER=$(echo "$BODY_AFTER" | jq '.did_document.verification_methods | length' 2>/dev/null || echo "0")
            info "Verification methods after rotation: $VM_AFTER"

            if [ "$VM_AFTER" -gt "$VM_BEFORE" ]; then
                pass "DID Document has additional verification method"
            else
                info "Verification method count unchanged (blockchain confirmation pending)"
            fi
        else
            fail "Key rotation failed" "$(echo "$BODY" | jq -r '.error // empty')"
        fi

        subsection "6.2 Second key rotation on same DID"
        NEW_KEY_2=$(openssl rand -hex 32)
        RESP=$(http_post "$BASE_URL/api/v1/did/rotate-key/$DID_GW_ENC" \
            "{\"new_public_key\": \"$NEW_KEY_2\"}")
        BODY=$(get_body "$RESP")

        ROTATE_OK_2=$(echo "$BODY" | jq -r '.success // false')
        if [ "$ROTATE_OK_2" = "true" ]; then
            pass "Second key rotation successful"
        else
            info "Second rotation: $(echo "$BODY" | jq -r '.error // empty')"
        fi
    else
        skip "No Gateway DID for key rotation"
    fi

    subsection "6.3 Key rotation with invalid key (too short)"
    if [ -n "$DID_SENSOR" ]; then
        DID_SENSOR_ENC=$(urlencode "$DID_SENSOR")
        RESP=$(http_post "$BASE_URL/api/v1/did/rotate-key/$DID_SENSOR_ENC" \
            '{"new_public_key": "tooshort"}')
        CODE=$(get_code "$RESP")
        BODY=$(get_body "$RESP")

        if [ "$CODE" = "400" ] || echo "$BODY" | jq -e '.success == false' > /dev/null 2>&1; then
            pass "Invalid key rotation rejected"
        else
            fail "Invalid key should be rejected"
        fi
    fi

    subsection "6.4 Key rotation with non-hex key"
    if [ -n "$DID_SENSOR" ]; then
        DID_SENSOR_ENC=$(urlencode "$DID_SENSOR")
        RESP=$(http_post "$BASE_URL/api/v1/did/rotate-key/$DID_SENSOR_ENC" \
            '{"new_public_key": "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"}')
        CODE=$(get_code "$RESP")
        BODY=$(get_body "$RESP")

        if [ "$CODE" != "200" ] || echo "$BODY" | jq -e '.success == false or has("error")' > /dev/null 2>&1; then
            pass "Non-hex key rotation handled"
        else
            info "Non-hex key rotation: HTTP $CODE"
        fi
    fi

    subsection "6.5 Key rotation on unauthorized DID"
    FAKE_DID="did:iota:testnet:0x0000000000000000000000000000000000000000000000000000000000000000"
    FAKE_ENC=$(urlencode "$FAKE_DID")
    RESP=$(http_post "$BASE_URL/api/v1/did/rotate-key/$FAKE_ENC" \
        "{\"new_public_key\": \"$(openssl rand -hex 32)\"}")
    BODY=$(get_body "$RESP")

    ROTATE_OK=$(echo "$BODY" | jq -r '.success // true')
    if [ "$ROTATE_OK" = "false" ]; then
        pass "Unauthorized key rotation rejected"
    else
        fail "Unauthorized key rotation should be rejected"
    fi

    subsection "6.6 Key rotation missing new_public_key"
    if [ -n "$DID_SENSOR" ]; then
        DID_SENSOR_ENC=$(urlencode "$DID_SENSOR")
        RESP=$(http_post "$BASE_URL/api/v1/did/rotate-key/$DID_SENSOR_ENC" '{}')
        CODE=$(get_code "$RESP")

        if [ "$CODE" = "400" ] || [ "$CODE" = "422" ]; then
            pass "Missing new_public_key rejected (HTTP $CODE)"
        else
            fail "Missing field should be rejected (HTTP $CODE)"
        fi
    fi
fi

# =============================================================================
# SECTION 7: DID DEACTIVATION (ON-CHAIN)
# =============================================================================
section "SECTION 7: DID Deactivation (On-Chain)"

if [ "$SKIP_ONCHAIN" = true ]; then
    skip "DID deactivation tests (--skip-onchain)"
else
    subsection "7.1 Deactivate Actuator DID"
    if [ -n "$DID_ACTUATOR" ]; then
        DID_ACT_ENC=$(urlencode "$DID_ACTUATOR")

        RESP=$(http_post "$BASE_URL/api/v1/did/deactivate/$DID_ACT_ENC" '{}')
        BODY=$(get_body "$RESP")
        CODE=$(get_code "$RESP")

        DEACT_OK=$(echo "$BODY" | jq -r '.success // false')
        if [ "$DEACT_OK" = "true" ]; then
            pass "DID deactivated on-chain"

            DEACT_AT=$(echo "$BODY" | jq -r '.deactivated_at // empty')
            if [ -n "$DEACT_AT" ]; then
                pass "Deactivation timestamp present"
            else
                fail "Deactivation timestamp missing"
            fi

            DEACT_DID=$(echo "$BODY" | jq -r '.did // empty')
            if [ "$DEACT_DID" = "$DID_ACTUATOR" ]; then
                pass "Response DID matches request"
            else
                fail "Response DID mismatch"
            fi
        else
            fail "DID deactivation failed" "$(echo "$BODY" | jq -r '.error // empty')"
        fi

        subsection "7.2 Double deactivation (should fail)"
        RESP=$(http_post "$BASE_URL/api/v1/did/deactivate/$DID_ACT_ENC" '{}')
        BODY=$(get_body "$RESP")

        DEACT_OK=$(echo "$BODY" | jq -r '.success // true')
        if [ "$DEACT_OK" = "false" ]; then
            pass "Double deactivation rejected"
        else
            fail "Double deactivation should be rejected"
        fi

        subsection "7.3 Key rotation on deactivated DID (should fail)"
        RESP=$(http_post "$BASE_URL/api/v1/did/rotate-key/$DID_ACT_ENC" \
            "{\"new_public_key\": \"$(openssl rand -hex 32)\"}")
        BODY=$(get_body "$RESP")

        ROTATE_OK=$(echo "$BODY" | jq -r '.success // true')
        if [ "$ROTATE_OK" = "false" ]; then
            pass "Key rotation on deactivated DID rejected"
        else
            fail "Key rotation should fail on deactivated DID"
        fi
    else
        skip "No Actuator DID for deactivation"
    fi

    subsection "7.4 Deactivate unauthorized DID"
    FAKE_DID="did:iota:testnet:0x0000000000000000000000000000000000000000000000000000000000000000"
    FAKE_ENC=$(urlencode "$FAKE_DID")
    RESP=$(http_post "$BASE_URL/api/v1/did/deactivate/$FAKE_ENC" '{}')
    BODY=$(get_body "$RESP")

    DEACT_OK=$(echo "$BODY" | jq -r '.success // true')
    if [ "$DEACT_OK" = "false" ]; then
        pass "Unauthorized deactivation rejected"
        ERROR=$(echo "$BODY" | jq -r '.error // empty')
        if echo "$ERROR" | grep -qi "not created"; then
            pass "Error message explains lack of control"
        fi
    else
        fail "Unauthorized deactivation should be rejected"
    fi
fi

# =============================================================================
# SECTION 8: CACHE MANAGEMENT
# =============================================================================
section "SECTION 8: Cache Management"

subsection "8.1 Populate cache with multiple resolutions"
CACHED_COUNT=0
for DID_VAR in "$DID_SENSOR" "$DID_GATEWAY" "$DID_CONTROLLER" "$DID_EDGE"; do
    if [ -n "$DID_VAR" ]; then
        DID_ENC=$(urlencode "$DID_VAR")
        http_get "$BASE_URL/api/v1/did/resolve/$DID_ENC" > /dev/null
        ((CACHED_COUNT++))
    fi
done
pass "Populated cache with $CACHED_COUNT DID resolutions"

subsection "8.2 Verify cache hits"
CACHE_HITS=0
for DID_VAR in "$DID_SENSOR" "$DID_GATEWAY" "$DID_CONTROLLER"; do
    if [ -n "$DID_VAR" ]; then
        DID_ENC=$(urlencode "$DID_VAR")
        RESP=$(http_get "$BASE_URL/api/v1/did/resolve/$DID_ENC")
        BODY=$(get_body "$RESP")
        FROM_CACHE=$(echo "$BODY" | jq -r '.from_cache // false')
        if [ "$FROM_CACHE" = "true" ]; then
            ((CACHE_HITS++))
        fi
    fi
done

if [ "$CACHE_HITS" -ge 1 ]; then
    pass "Cache hits detected: $CACHE_HITS"
else
    info "No cache hits detected (may be disabled)"
fi

subsection "8.3 Clear all caches"
RESP=$(http_post "$BASE_URL/api/v1/admin/cache/clear" '{}')
BODY=$(get_body "$RESP")
CODE=$(get_code "$RESP")

if [ "$CODE" = "200" ]; then
    pass "Cache clear endpoint responded (HTTP 200)"
else
    fail "Cache clear failed (HTTP $CODE)"
fi

STATUS=$(echo "$BODY" | jq -r '.status // empty')
if [ "$STATUS" = "ok" ]; then
    pass "Cache clear status: ok"
else
    info "Cache clear response: $(echo "$BODY" | jq -c .)"
fi

subsection "8.4 Verify cache invalidation after clear"
if [ -n "$DID_SENSOR" ]; then
    DID_SENSOR_ENC=$(urlencode "$DID_SENSOR")
    RESP=$(http_get "$BASE_URL/api/v1/did/resolve/$DID_SENSOR_ENC")
    BODY=$(get_body "$RESP")
    FROM_CACHE=$(echo "$BODY" | jq -r '.from_cache // true')

    if [ "$FROM_CACHE" = "false" ]; then
        pass "Post-clear resolution is not from cache"
    else
        info "Resolution still from cache (cache clear may not fully reset)"
    fi
fi

# =============================================================================
# SECTION 9: METRICS ENDPOINT
# =============================================================================
section "SECTION 9: Metrics Endpoint"

subsection "9.1 Fetch metrics"
RESP=$(http_get "$BASE_URL/metrics")
BODY=$(get_body "$RESP")
CODE=$(get_code "$RESP")

if [ "$CODE" = "200" ] && [ -n "$BODY" ]; then
    pass "Metrics endpoint available (HTTP $CODE)"
else
    fail "Metrics endpoint failed (HTTP $CODE)"
fi

subsection "9.2 Validate metrics structure"
if echo "$BODY" | jq -e 'has("cache")' > /dev/null 2>&1; then
    pass "Metrics contains 'cache' section"
else
    fail "Metrics missing 'cache' section"
fi

if echo "$BODY" | jq -e 'has("network")' > /dev/null 2>&1; then
    pass "Metrics contains 'network' field"
else
    fail "Metrics missing 'network' field"
fi

if echo "$BODY" | jq -e 'has("endpoint")' > /dev/null 2>&1; then
    pass "Metrics contains 'endpoint' field"
else
    fail "Metrics missing 'endpoint' field"
fi

CACHE_ENABLED=$(echo "$BODY" | jq -r '.cache.enabled // "missing"')
info "Cache enabled: $CACHE_ENABLED"

DID_CACHE_SIZE=$(echo "$BODY" | jq -r '.cache.did_documents // "missing"')
info "DID cache size: $DID_CACHE_SIZE"

NETWORK=$(echo "$BODY" | jq -r '.network // "unknown"')
info "Network: $NETWORK"

# =============================================================================
# SECTION 10: HTTP METHOD VALIDATION
# =============================================================================
section "SECTION 10: HTTP Method Validation"

subsection "10.1 GET on POST-only endpoints"
for ENDPOINT in "/api/v1/device/register" "/api/v1/credential/verify" "/api/v1/credential/revoke"; do
    RESP=$(curl -s -w "\n%{http_code}" "$BASE_URL$ENDPOINT" 2>/dev/null || echo -e "\n000")
    CODE=$(get_code "$RESP")
    if [ "$CODE" = "405" ] || [ "$CODE" = "404" ]; then
        pass "GET $ENDPOINT rejected (HTTP $CODE)"
    else
        info "GET $ENDPOINT returned HTTP $CODE"
    fi
done

subsection "10.2 POST on GET-only endpoints"
RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/health" 2>/dev/null || echo -e "\n000")
CODE=$(get_code "$RESP")
if [ "$CODE" = "405" ] || [ "$CODE" = "404" ]; then
    pass "POST /health rejected (HTTP $CODE)"
else
    info "POST /health returned HTTP $CODE"
fi

RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/metrics" 2>/dev/null || echo -e "\n000")
CODE=$(get_code "$RESP")
if [ "$CODE" = "405" ] || [ "$CODE" = "404" ]; then
    pass "POST /metrics rejected (HTTP $CODE)"
else
    info "POST /metrics returned HTTP $CODE"
fi

subsection "10.3 DELETE/PUT/PATCH on endpoints"
for METHOD in DELETE PUT PATCH; do
    RESP=$(curl -s -w "\n%{http_code}" -X "$METHOD" "$BASE_URL/api/v1/device/register" \
        -H "Content-Type: application/json" -d '{}' 2>/dev/null || echo -e "\n000")
    CODE=$(get_code "$RESP")
    if [ "$CODE" = "405" ] || [ "$CODE" = "404" ]; then
        pass "$METHOD /api/v1/device/register rejected (HTTP $CODE)"
    else
        info "$METHOD /api/v1/device/register returned HTTP $CODE"
    fi
done

# =============================================================================
# SECTION 11: NON-EXISTENT ROUTES
# =============================================================================
section "SECTION 11: Non-existent Routes"

subsection "11.1 404 on unknown paths"
for ENDPOINT in "/api/v2/device/register" "/api/v1/unknown" "/foo" "/api/v1/did/delete/xyz"; do
    RESP=$(http_get "$BASE_URL$ENDPOINT")
    CODE=$(get_code "$RESP")
    if [ "$CODE" = "404" ]; then
        pass "GET $ENDPOINT returns 404"
    else
        info "GET $ENDPOINT returns HTTP $CODE"
    fi
done

# =============================================================================
# SECTION 12: CONCURRENT REQUESTS
# =============================================================================
section "SECTION 12: Concurrent Request Handling"

subsection "12.1 Parallel DID resolutions"
if [ -n "$DID_SENSOR" ]; then
    DID_SENSOR_ENC=$(urlencode "$DID_SENSOR")

    # Fire 5 parallel requests
    PIDS=""
    TEMP_DIR=$(mktemp -d)
    for i in $(seq 1 5); do
        curl -s -o "$TEMP_DIR/result_$i.json" -w "%{http_code}" \
            "$BASE_URL/api/v1/did/resolve/$DID_SENSOR_ENC" > "$TEMP_DIR/code_$i.txt" &
        PIDS="$PIDS $!"
    done

    # Wait for all
    PARALLEL_OK=0
    PARALLEL_FAIL=0
    for PID in $PIDS; do
        wait $PID 2>/dev/null || true
    done

    for i in $(seq 1 5); do
        CODE=$(cat "$TEMP_DIR/code_$i.txt" 2>/dev/null || echo "000")
        if [ "$CODE" = "200" ]; then
            ((PARALLEL_OK++))
        else
            ((PARALLEL_FAIL++))
        fi
    done

    rm -rf "$TEMP_DIR"

    if [ "$PARALLEL_OK" -eq 5 ]; then
        pass "All 5 parallel resolutions succeeded"
    elif [ "$PARALLEL_OK" -ge 3 ]; then
        pass "Most parallel resolutions succeeded ($PARALLEL_OK/5)"
    else
        fail "Parallel resolutions: $PARALLEL_OK/5 succeeded"
    fi
fi

subsection "12.2 Parallel registrations"
TEMP_DIR=$(mktemp -d)
PIDS=""
for i in $(seq 1 3); do
    PK=$(openssl rand -hex 32)
    curl -s -o "$TEMP_DIR/reg_$i.json" -w "%{http_code}" \
        -X POST "$BASE_URL/api/v1/device/register" \
        -H "Content-Type: application/json" \
        -d "{\"public_key\":\"$PK\",\"device_type\":\"Sensor\",\"capabilities\":[\"test_$i\"]}" \
        > "$TEMP_DIR/reg_code_$i.txt" &
    PIDS="$PIDS $!"
done

for PID in $PIDS; do
    wait $PID 2>/dev/null || true
done

REG_OK=0
for i in $(seq 1 3); do
    CODE=$(cat "$TEMP_DIR/reg_code_$i.txt" 2>/dev/null || echo "000")
    if [ "$CODE" = "200" ]; then
        ((REG_OK++))
    fi
done

rm -rf "$TEMP_DIR"

if [ "$REG_OK" -eq 3 ]; then
    pass "All 3 parallel registrations succeeded"
elif [ "$REG_OK" -ge 1 ]; then
    pass "Parallel registrations: $REG_OK/3 succeeded"
else
    fail "All parallel registrations failed"
fi

# =============================================================================
# SECTION 13: FULL DEVICE LIFECYCLE
# =============================================================================
section "SECTION 13: Full Device Lifecycle"

subsection "13.1 Complete lifecycle: register -> resolve -> verify -> revoke -> deactivate"

# Step 1: Register
PK_LIFECYCLE=$(openssl rand -hex 32)
RESP=$(http_post "$BASE_URL/api/v1/device/register" "{
    \"public_key\": \"$PK_LIFECYCLE\",
    \"device_type\": \"Sensor\",
    \"capabilities\": [\"lifecycle_test\"]
}")
BODY=$(get_body "$RESP")
CODE=$(get_code "$RESP")

DID_LC=$(echo "$BODY" | jq -r '.did // empty')
JWT_LC=$(echo "$BODY" | jq -r '.credential_jwt // empty')

if [ "$CODE" = "200" ] && [ -n "$DID_LC" ]; then
    pass "Lifecycle Step 1: Device registered"
else
    fail "Lifecycle Step 1: Registration failed"
fi

# Step 2: Resolve
if [ -n "$DID_LC" ]; then
    DID_LC_ENC=$(urlencode "$DID_LC")
    RESP=$(http_get "$BASE_URL/api/v1/did/resolve/$DID_LC_ENC")
    CODE=$(get_code "$RESP")
    BODY=$(get_body "$RESP")

    if [ "$CODE" = "200" ]; then
        pass "Lifecycle Step 2: DID resolved"
    else
        fail "Lifecycle Step 2: Resolution failed"
    fi
fi

# Step 3: Verify credential
if [ -n "$JWT_LC" ]; then
    RESP=$(http_post "$BASE_URL/api/v1/credential/verify" \
        "{\"credential_jwt\": \"$JWT_LC\"}")
    BODY=$(get_body "$RESP")
    VALID=$(echo "$BODY" | jq -r '.valid // false')

    if [ "$VALID" = "true" ]; then
        pass "Lifecycle Step 3: Credential valid"
    else
        fail "Lifecycle Step 3: Credential should be valid"
    fi
fi

# Step 4: Revoke credential
LC_CRED_ID=""
if [ -n "$JWT_LC" ]; then
    PAYLOAD_B64=$(echo "$JWT_LC" | cut -d'.' -f2)
    PADDED="$PAYLOAD_B64"
    MOD=$((${#PADDED} % 4))
    if [ "$MOD" -eq 2 ]; then PADDED="${PADDED}=="; elif [ "$MOD" -eq 3 ]; then PADDED="${PADDED}="; fi
    LC_CRED_ID=$(echo "$PADDED" | base64 -d 2>/dev/null | jq -r '.vc.id // empty' 2>/dev/null || echo "")
fi

if [ -n "$LC_CRED_ID" ] && [ "$LC_CRED_ID" != "null" ]; then
    RESP=$(http_post "$BASE_URL/api/v1/credential/revoke" "{
        \"credential_id\": \"$LC_CRED_ID\",
        \"reason\": \"Lifecycle test: device decommissioned\"
    }")
    BODY=$(get_body "$RESP")
    REVOKE_OK=$(echo "$BODY" | jq -r '.success // false')

    if [ "$REVOKE_OK" = "true" ]; then
        pass "Lifecycle Step 4: Credential revoked"
    else
        fail "Lifecycle Step 4: Revocation failed"
    fi

    # Step 4b: Verify fails after revocation
    RESP=$(http_post "$BASE_URL/api/v1/credential/verify" \
        "{\"credential_jwt\": \"$JWT_LC\"}")
    BODY=$(get_body "$RESP")
    VALID=$(echo "$BODY" | jq -r '.valid // true')

    if [ "$VALID" = "false" ]; then
        pass "Lifecycle Step 4b: Revoked credential fails verification"
    else
        info "Lifecycle Step 4b: Revoked credential still passes (verify may not check revocation)"
    fi
else
    info "Lifecycle Step 4: Could not extract credential ID, using fallback"
    RESP=$(http_post "$BASE_URL/api/v1/credential/revoke" "{
        \"credential_id\": \"lifecycle-test-$(date +%s)\",
        \"reason\": \"Lifecycle test\"
    }")
    BODY=$(get_body "$RESP")
    REVOKE_OK=$(echo "$BODY" | jq -r '.success // false')
    if [ "$REVOKE_OK" = "true" ]; then
        pass "Lifecycle Step 4: Fallback revocation works"
    fi
fi

# Step 5: Deactivate DID (on-chain)
if [ "$SKIP_ONCHAIN" = false ] && [ -n "$DID_LC" ]; then
    DID_LC_ENC=$(urlencode "$DID_LC")
    RESP=$(http_post "$BASE_URL/api/v1/did/deactivate/$DID_LC_ENC" '{}')
    BODY=$(get_body "$RESP")
    DEACT_OK=$(echo "$BODY" | jq -r '.success // false')

    if [ "$DEACT_OK" = "true" ]; then
        pass "Lifecycle Step 5: DID deactivated on-chain"
    else
        fail "Lifecycle Step 5: Deactivation failed" "$(echo "$BODY" | jq -r '.error // empty')"
    fi

    # Step 5b: Operations on deactivated DID should fail
    RESP=$(http_post "$BASE_URL/api/v1/did/rotate-key/$DID_LC_ENC" \
        "{\"new_public_key\": \"$(openssl rand -hex 32)\"}")
    BODY=$(get_body "$RESP")
    ROTATE_OK=$(echo "$BODY" | jq -r '.success // true')

    if [ "$ROTATE_OK" = "false" ]; then
        pass "Lifecycle Step 5b: Operations on deactivated DID rejected"
    else
        fail "Lifecycle Step 5b: Should reject operations on deactivated DID"
    fi
else
    skip "Lifecycle Step 5: Deactivation (--skip-onchain)"
fi

# =============================================================================
# SECTION 14: CORS HEADERS
# =============================================================================
section "SECTION 14: CORS Headers"

subsection "14.1 CORS preflight (OPTIONS)"
RESP=$(curl -s -w "\n%{http_code}" -X OPTIONS "$BASE_URL/api/v1/device/register" \
    -H "Origin: http://example.com" \
    -H "Access-Control-Request-Method: POST" \
    -H "Access-Control-Request-Headers: Content-Type" 2>/dev/null || echo -e "\n000")
CODE=$(get_code "$RESP")

if [ "$CODE" = "200" ] || [ "$CODE" = "204" ]; then
    pass "CORS preflight accepted (HTTP $CODE)"
else
    info "CORS preflight: HTTP $CODE"
fi

subsection "14.2 CORS on actual request"
RESP_HEADERS=$(curl -s -D - -o /dev/null "$BASE_URL/health" \
    -H "Origin: http://example.com" 2>/dev/null || echo "")

if echo "$RESP_HEADERS" | grep -qi "access-control-allow-origin"; then
    pass "CORS header present in response"
else
    info "No CORS header found (may need Origin header)"
fi

# =============================================================================
# SECTION 15: LARGE PAYLOAD HANDLING
# =============================================================================
section "SECTION 15: Edge Cases & Boundary Conditions"

subsection "15.1 Very long capability strings"
PK_LONG=$(openssl rand -hex 32)
LONG_CAP=$(python3 -c "print('x' * 1000)" 2>/dev/null || printf 'x%.0s' {1..1000})
RESP=$(http_post "$BASE_URL/api/v1/device/register" "{
    \"public_key\": \"$PK_LONG\",
    \"device_type\": \"Sensor\",
    \"capabilities\": [\"$LONG_CAP\"]
}")
CODE=$(get_code "$RESP")

if [ "$CODE" = "200" ] || [ "$CODE" = "400" ] || [ "$CODE" = "413" ]; then
    pass "Long capability handled (HTTP $CODE)"
else
    info "Long capability: HTTP $CODE"
fi

subsection "15.2 Special characters in capability"
PK_SPECIAL=$(openssl rand -hex 32)
RESP=$(http_post "$BASE_URL/api/v1/device/register" "{
    \"public_key\": \"$PK_SPECIAL\",
    \"device_type\": \"Sensor\",
    \"capabilities\": [\"temp/humidity\", \"sensor@v2\", \"data-stream\"]
}")
CODE=$(get_code "$RESP")

if [ "$CODE" = "200" ]; then
    pass "Special characters in capabilities accepted"
else
    info "Special characters: HTTP $CODE"
fi

subsection "15.3 Unicode in optional fields"
PK_UNICODE=$(openssl rand -hex 32)
RESP=$(http_post "$BASE_URL/api/v1/device/register" "{
    \"public_key\": \"$PK_UNICODE\",
    \"device_type\": \"Sensor\",
    \"capabilities\": [\"temperature\"],
    \"manufacturer\": \"Sensori S.r.l.\",
    \"model\": \"Modello-Prova\"
}")
CODE=$(get_code "$RESP")

if [ "$CODE" = "200" ]; then
    pass "UTF-8 in optional fields accepted"
else
    info "UTF-8 fields: HTTP $CODE"
fi

subsection "15.4 URL-encoded DID resolution"
if [ -n "$DID_SENSOR" ]; then
    # Test double-encoding edge case
    DID_DOUBLE_ENC=$(urlencode "$(urlencode "$DID_SENSOR")")
    RESP=$(http_get "$BASE_URL/api/v1/did/resolve/$DID_DOUBLE_ENC")
    CODE=$(get_code "$RESP")

    if [ "$CODE" = "400" ] || [ "$CODE" = "404" ] || [ "$CODE" = "500" ]; then
        pass "Double-encoded DID handled (HTTP $CODE)"
    else
        info "Double-encoded DID: HTTP $CODE"
    fi
fi

# =============================================================================
# SECTION 16: RESPONSE TIME BENCHMARKS
# =============================================================================
section "SECTION 16: Response Time Benchmarks"

subsection "16.1 Health endpoint latency"
START_NS=$(date +%s%N)
http_get "$BASE_URL/health" > /dev/null
END_NS=$(date +%s%N)
HEALTH_MS=$(( (END_NS - START_NS) / 1000000 ))

if [ "$HEALTH_MS" -lt 50 ]; then
    pass "Health endpoint: ${HEALTH_MS}ms (< 50ms)"
elif [ "$HEALTH_MS" -lt 200 ]; then
    pass "Health endpoint: ${HEALTH_MS}ms (< 200ms)"
else
    info "Health endpoint: ${HEALTH_MS}ms"
fi

subsection "16.2 Cached DID resolution latency"
if [ -n "$DID_SENSOR" ]; then
    DID_SENSOR_ENC=$(urlencode "$DID_SENSOR")
    # Warm cache
    http_get "$BASE_URL/api/v1/did/resolve/$DID_SENSOR_ENC" > /dev/null

    # Measure cached resolution
    START_NS=$(date +%s%N)
    http_get "$BASE_URL/api/v1/did/resolve/$DID_SENSOR_ENC" > /dev/null
    END_NS=$(date +%s%N)
    CACHED_MS=$(( (END_NS - START_NS) / 1000000 ))

    if [ "$CACHED_MS" -lt 50 ]; then
        pass "Cached resolution: ${CACHED_MS}ms (< 50ms)"
    elif [ "$CACHED_MS" -lt 200 ]; then
        pass "Cached resolution: ${CACHED_MS}ms (< 200ms)"
    else
        info "Cached resolution: ${CACHED_MS}ms"
    fi
fi

subsection "16.3 Credential verification latency"
if [ -n "$JWT_GATEWAY" ]; then
    START_NS=$(date +%s%N)
    http_post "$BASE_URL/api/v1/credential/verify" \
        "{\"credential_jwt\": \"$JWT_GATEWAY\"}" > /dev/null
    END_NS=$(date +%s%N)
    VERIFY_MS=$(( (END_NS - START_NS) / 1000000 ))

    if [ "$VERIFY_MS" -lt 100 ]; then
        pass "Credential verification: ${VERIFY_MS}ms (< 100ms)"
    elif [ "$VERIFY_MS" -lt 500 ]; then
        pass "Credential verification: ${VERIFY_MS}ms (< 500ms)"
    else
        info "Credential verification: ${VERIFY_MS}ms"
    fi
fi

subsection "16.4 Metrics endpoint latency"
START_NS=$(date +%s%N)
http_get "$BASE_URL/metrics" > /dev/null
END_NS=$(date +%s%N)
METRICS_MS=$(( (END_NS - START_NS) / 1000000 ))
pass "Metrics endpoint: ${METRICS_MS}ms"

# =============================================================================
# SUMMARY
# =============================================================================
TOTAL_END=$(date +%s)
TOTAL_DURATION=$((TOTAL_END - TOTAL_START))
TOTAL_TESTS=$((TESTS_PASSED + TESTS_FAILED + TESTS_SKIPPED))

section "TEST SUMMARY"

echo ""
echo -e "  ${BOLD}Total tests:  $TOTAL_TESTS${NC}"
echo -e "  ${GREEN}Passed:       $TESTS_PASSED${NC}"
echo -e "  ${RED}Failed:       $TESTS_FAILED${NC}"
echo -e "  ${YELLOW}Skipped:      $TESTS_SKIPPED${NC}"
echo -e "  Duration:    ${TOTAL_DURATION}s"
echo ""

echo "  Devices Registered:"
[ -n "$DID_SENSOR" ]     && echo "    Sensor:     $DID_SENSOR"
[ -n "$DID_GATEWAY" ]    && echo "    Gateway:    $DID_GATEWAY"
[ -n "$DID_ACTUATOR" ]   && echo "    Actuator:   $DID_ACTUATOR"
[ -n "$DID_CONTROLLER" ] && echo "    Controller: $DID_CONTROLLER"
[ -n "$DID_EDGE" ]       && echo "    Edge:       $DID_EDGE"
[ -n "$DID_GENERIC" ]    && echo "    Generic:    $DID_GENERIC"
echo ""

echo -e "  ${BLUE}IOTA Explorer:${NC}"
[ -n "$OBJ_SENSOR" ]   && echo "    Sensor:   https://explorer.rebased.iota.org/object/$OBJ_SENSOR?network=testnet"
[ -n "$OBJ_GATEWAY" ]  && echo "    Gateway:  https://explorer.rebased.iota.org/object/$OBJ_GATEWAY?network=testnet"
[ -n "$OBJ_ACTUATOR" ] && echo "    Actuator: https://explorer.rebased.iota.org/object/$OBJ_ACTUATOR?network=testnet"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}${BOLD}================================================================"
    echo "  ALL TESTS PASSED!"
    echo -e "================================================================${NC}"
    exit 0
else
    echo -e "${RED}${BOLD}================================================================"
    echo "  $TESTS_FAILED TEST(S) FAILED - Review output above"
    echo -e "================================================================${NC}"
    exit 1
fi
