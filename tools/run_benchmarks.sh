#!/bin/bash
# =============================================================================
# IOTA Identity IoT - Full Benchmark Runner
# =============================================================================
# This script runs all benchmarks against the IOTA testnet.
#
# Prerequisites:
# - Rust toolchain installed
# - Funded issuer wallet (~80 IOTA available)
# - issuer_identity.json exists in ~/.iota-identity-service/
#
# Usage:
#   ./run_benchmarks.sh              # Run with default iterations
#   ./run_benchmarks.sh --iterations 20  # Run with more iterations
#   ./run_benchmarks.sh --fast       # Run only fast benchmarks
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
IDENTITY_SERVICE_PORT=8080
IDENTITY_SERVICE_URL="http://localhost:$IDENTITY_SERVICE_PORT"
OUTPUT_DIR="$PROJECT_ROOT/benchmark-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SERVICE_PID=""
ITERATIONS=${ITERATIONS:-10}
FAST_ONLY=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --iterations)
            ITERATIONS="$2"
            shift 2
            ;;
        --fast)
            FAST_ONLY=true
            shift
            ;;
        --help)
            echo "Usage: $0 [--iterations N] [--fast]"
            echo ""
            echo "Options:"
            echo "  --iterations N   Number of iterations per benchmark (default: 10)"
            echo "  --fast           Run only fast benchmarks (skip DID creation)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

cleanup() {
    log_info "Cleaning up..."
    if [ -n "$SERVICE_PID" ] && ps -p $SERVICE_PID > /dev/null 2>&1; then
        log_info "Stopping identity-service (PID: $SERVICE_PID)"
        kill $SERVICE_PID 2>/dev/null || true
        wait $SERVICE_PID 2>/dev/null || true
    fi
}

trap cleanup EXIT

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check Rust
    if ! command -v cargo &> /dev/null; then
        log_error "Rust/Cargo not found. Please install Rust."
        exit 1
    fi
    log_success "Rust/Cargo found"
    
    # Check issuer_identity.json
    ISSUER_FILE="$HOME/.iota-identity-service/issuer_identity.json"
    if [ ! -f "$ISSUER_FILE" ]; then
        log_error "Issuer identity not found at $ISSUER_FILE"
        log_info "Please run the identity-service once to create an issuer, or copy your existing issuer_identity.json"
        exit 1
    fi
    log_success "Issuer identity found"
    
    # Check balance
    if command -v python3 &> /dev/null && [ -f "$SCRIPT_DIR/derive_address.py" ]; then
        log_info "Checking issuer wallet balance..."
        ADDRESS=$(python3 "$SCRIPT_DIR/derive_address.py" -f "$ISSUER_FILE" 2>/dev/null | grep "0x" | head -1 | tr -d ' ')
        if [ -n "$ADDRESS" ]; then
            BALANCE_RESPONSE=$(curl -s -X POST https://api.testnet.iota.cafe:443 \
                -H "Content-Type: application/json" \
                -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"iotax_getBalance\",\"params\":[\"$ADDRESS\"]}")
            BALANCE=$(echo "$BALANCE_RESPONSE" | grep -o '"totalBalance":"[^"]*"' | cut -d'"' -f4)
            if [ -n "$BALANCE" ]; then
                BALANCE_IOTA=$((BALANCE / 1000000000))
                log_success "Issuer balance: $BALANCE_IOTA IOTA ($BALANCE NANOS)"
                if [ "$BALANCE_IOTA" -lt 10 ]; then
                    log_warning "Balance is low. Consider requesting more funds from faucet."
                fi
            fi
        fi
    fi
}

build_project() {
    log_info "Building project in release mode..."
    cd "$PROJECT_ROOT"
    cargo build --release 2>&1 | tail -10
    log_success "Build complete"
}

start_identity_service() {
    log_info "Starting identity-service..."
    
    # Check if already running
    if curl -s "$IDENTITY_SERVICE_URL/health" > /dev/null 2>&1; then
        log_warning "Identity service already running on port $IDENTITY_SERVICE_PORT"
        return 0
    fi
    
    # Start the service
    cd "$PROJECT_ROOT"
    RUST_LOG=info cargo run --release --package identity-service > "$OUTPUT_DIR/identity-service.log" 2>&1 &
    SERVICE_PID=$!
    
    log_info "Waiting for identity-service to start (PID: $SERVICE_PID)..."
    
    # Wait for service to be ready (max 120 seconds for issuer initialization)
    MAX_WAIT=120
    WAITED=0
    while ! curl -s "$IDENTITY_SERVICE_URL/health" > /dev/null 2>&1; do
        sleep 2
        WAITED=$((WAITED + 2))
        if [ $WAITED -ge $MAX_WAIT ]; then
            log_error "Identity service failed to start within ${MAX_WAIT}s"
            log_info "Check logs at: $OUTPUT_DIR/identity-service.log"
            tail -50 "$OUTPUT_DIR/identity-service.log"
            exit 1
        fi
        # Show progress
        if [ $((WAITED % 10)) -eq 0 ]; then
            log_info "Still waiting... ($WAITED/${MAX_WAIT}s)"
        fi
    done
    
    log_success "Identity service is ready"
}

run_benchmarks() {
    log_info "Running benchmarks with $ITERATIONS iterations..."
    
    mkdir -p "$OUTPUT_DIR"
    
    RESULT_FILE="$OUTPUT_DIR/benchmark_results_$TIMESTAMP.csv"
    LOG_FILE="$OUTPUT_DIR/benchmark_log_$TIMESTAMP.txt"
    
    cd "$PROJECT_ROOT"
    
    if [ "$FAST_ONLY" = true ]; then
        log_info "Running fast benchmarks only..."
        
        # Run individual fast benchmarks
        for benchmark in did-resolution-cached credential-verification revocation-check; do
            log_info "Running: $benchmark"
            cargo run --release --package benchmarks -- \
                --benchmark $benchmark \
                --iterations $ITERATIONS \
                --identity-service "$IDENTITY_SERVICE_URL" \
                2>&1 | tee -a "$LOG_FILE"
        done
    else
        log_info "Running all benchmarks..."
        
        # Run all benchmarks and save results
        cargo run --release --package benchmarks -- \
            --all \
            --iterations $ITERATIONS \
            --identity-service "$IDENTITY_SERVICE_URL" \
            --output "$RESULT_FILE" \
            2>&1 | tee "$LOG_FILE"
    fi
    
    log_success "Benchmarks complete!"
    log_info "Results saved to: $RESULT_FILE"
    log_info "Full log saved to: $LOG_FILE"
}

print_summary() {
    echo ""
    echo "============================================================"
    echo "                    BENCHMARK COMPLETE"
    echo "============================================================"
    echo ""
    echo "Output directory: $OUTPUT_DIR"
    echo ""
    
    if [ -f "$OUTPUT_DIR/benchmark_results_$TIMESTAMP.csv" ]; then
        echo "Results file: benchmark_results_$TIMESTAMP.csv"
        echo ""
        echo "CSV Contents:"
        echo "-------------"
        cat "$OUTPUT_DIR/benchmark_results_$TIMESTAMP.csv"
    fi
    
    echo ""
    echo "============================================================"
    echo ""
}

# =============================================================================
# Main
# =============================================================================

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     IOTA Identity IoT - Benchmark Runner                   ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "Configuration:"
echo "  Project Root: $PROJECT_ROOT"
echo "  Iterations: $ITERATIONS"
echo "  Fast Only: $FAST_ONLY"
echo "  Timestamp: $TIMESTAMP"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Run steps
check_prerequisites
build_project
start_identity_service
run_benchmarks
print_summary

log_success "All done!"