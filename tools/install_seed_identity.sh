#!/usr/bin/env bash
# Install the pre-funded seed issuer identity so that identity-service starts
# in an already-initialised state without calling the testnet faucet.
#
# Usage (from the repository root):
#   bash tools/install_seed_identity.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SEED_FILE="$REPO_ROOT/tools/seed/issuer_identity.json"
STORAGE_DIR="$HOME/.iota-identity-service"
DEST="$STORAGE_DIR/issuer_identity.json"

if [ ! -f "$SEED_FILE" ]; then
    echo "Error: seed identity file not found at $SEED_FILE"
    echo "Run 'python3 tools/create_seed_identity.py' and follow the printed steps"
    echo "to generate and populate the seed file first."
    exit 1
fi

mkdir -p "$STORAGE_DIR"

if [ -f "$DEST" ]; then
    echo "Warning: an existing issuer identity was found at $DEST"
    printf "Overwrite it with the seed identity? [y/N] "
    read -r REPLY
    if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
        echo "Aborted — existing identity left unchanged."
        exit 0
    fi
    cp "$DEST" "${DEST}.bak"
    echo "Backup saved to ${DEST}.bak"
fi

cp "$SEED_FILE" "$DEST"
echo "Seed identity installed at $DEST"
echo "You can now start identity-service; the issuer is pre-initialised."
