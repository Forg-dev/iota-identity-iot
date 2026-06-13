#!/usr/bin/env python3
"""Generate key material for a fresh seed issuer identity.

Without --fund: generates keys, writes the pending JSON, and prints the manual
transfer command.

With --fund: also executes the transfer automatically via the IOTA CLI (requires
`iota` in PATH with an active account that has sufficient testnet balance).

Usage
-----
  python3 tools/create_seed_identity.py           # generate + print instructions
  python3 tools/create_seed_identity.py --fund    # generate + transfer automatically

After either mode, follow the remaining steps printed at the end.
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat, PublicFormat,
    )
except ImportError:
    sys.exit("Missing dependency: pip install cryptography")

import hashlib

TRANSFER_AMOUNT =  5_000_000_000   # 5 IOTA in nanos (sufficient for ~1000 DID operations)
GAS_BUDGET      =  5_000_000       # 0.005 IOTA


def generate_ed25519_keypair():
    priv = Ed25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_bytes  = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv_bytes, pub_bytes


def iota_address_from_ed25519_pub(pub_bytes: bytes) -> str:
    """Derive an IOTA Rebased / Sui address from an Ed25519 public key.

    address = first 32 bytes of Blake2b-256( 0x00 || pub_key )
    """
    digest = hashlib.blake2b(bytes([0x00]) + pub_bytes, digest_size=32).digest()
    return "0x" + digest.hex()


def get_gas_coins() -> list:
    """Return gas coin objects from the active IOTA account."""
    result = subprocess.run(
        ["iota", "client", "gas", "--json"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"  iota client gas failed: {result.stderr.strip()}")
        return []
    try:
        data = json.loads(result.stdout)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("data", data.get("coins", []))
    except json.JSONDecodeError as e:
        print(f"  Could not parse gas output: {e}")
        print(f"  Raw output: {result.stdout[:300]}")
    return []


def fund_via_cli(tx_address: str) -> bool:
    """Call `iota client pay-iota` and return True on success."""
    print("Querying gas coins from active IOTA account...")
    coins = get_gas_coins()
    if not coins:
        print("No gas coins found. Make sure `iota client` is configured and funded.")
        return False

    # Find a coin with enough balance; try common field names used by different CLI versions
    coin_id = None
    for coin in coins:
        cid = (coin.get("gasCoinId") or coin.get("id") or
               coin.get("objectId") or coin.get("coinObjectId"))
        raw_balance = (coin.get("nanosBalance") or coin.get("mistBalance") or
                       coin.get("nanoBalance") or coin.get("balance") or "0")
        try:
            balance = int(raw_balance)
        except (ValueError, TypeError):
            continue
        if cid and balance >= TRANSFER_AMOUNT + GAS_BUDGET:
            coin_id = cid
            break

    if not coin_id:
        print("No coin with sufficient balance found.")
        print(f"Available coins: {json.dumps(coins, indent=2)}")
        return False

    cmd = [
        "iota", "client", "pay-iota",
        "--input-coins", coin_id,
        "--recipients", tx_address,
        "--amounts", str(TRANSFER_AMOUNT),
        "--gas-budget", str(GAS_BUDGET),
        "--json",
    ]
    print(f"Running: {' '.join(cmd)}\n")
    result = subprocess.run(cmd, capture_output=False, text=True)
    return result.returncode == 0


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--fund", action="store_true",
                        help="automatically transfer IOTA via the CLI after key generation")
    args = parser.parse_args()

    print("Generating seed issuer identity key material...\n")

    signing_priv, _ = generate_ed25519_keypair()
    tx_priv, tx_pub  = generate_ed25519_keypair()

    signing_key_hex = signing_priv.hex()
    tx_key_hex      = tx_priv.hex()
    tx_address      = iota_address_from_ed25519_pub(tx_pub)

    storage_dir   = Path.home() / ".iota-identity-service"
    storage_dir.mkdir(parents=True, exist_ok=True)
    identity_file = storage_dir / "issuer_identity.json"

    pending = {
        "did": "pending",
        "signing_key_hex": signing_key_hex,
        "tx_key_hex": tx_key_hex,
        "next_revocation_index": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    identity_file.write_text(json.dumps(pending, indent=2))

    print(f"Pending identity written to: {identity_file}")
    print(f"Tx key address:              {tx_address}\n")

    if args.fund:
        print(f"Transferring {TRANSFER_AMOUNT // 10**9} IOTA to {tx_address} via IOTA CLI...\n")
        success = fund_via_cli(tx_address)
        if success:
            print("\nTransfer successful.")
        else:
            print("\nTransfer failed. Fund the address manually, then continue with the steps below.")
    else:
        print("To fund the address manually, run:")
        print(f"  iota client transfer-iota \\")
        print(f"    --to {tx_address} \\")
        print(f"    --amount {TRANSFER_AMOUNT} \\")
        print(f"    --gas-budget {GAS_BUDGET}")
        print()
        print("Or re-run with --fund to do this automatically:")
        print("  python3 tools/create_seed_identity.py --fund")

    print()
    print("=" * 60)
    print("Remaining steps (after the address is funded):")
    print()
    print("  1. Start identity-service:")
    print("       cargo run --release -p identity-service")
    print()
    print("  2. Initialise the issuer DID on-chain:")
    print("       curl -s -X POST http://localhost:3000/api/v1/issuer/initialize | jq .")
    print()
    print("  3. Copy the finalised identity into the repo seed directory:")
    print(f"       cp {identity_file} tools/seed/issuer_identity.json")
    print()
    print("  4. Commit tools/seed/issuer_identity.json.")
    print("=" * 60)


if __name__ == "__main__":
    main()
