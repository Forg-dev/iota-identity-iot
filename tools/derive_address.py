#!/usr/bin/env python3
"""
Derive IOTA Rebased address from issuer_identity.json tx_key_hex

IOTA Rebased address derivation:
1. Take Ed25519 private key (32 bytes)
2. Derive public key using Ed25519
3. Hash public key directly with Blake2b-256 (NO flag byte prefix)
4. Result is the 32-byte address
"""

import hashlib
import json
import sys
from pathlib import Path

# Try to use cryptography library for Ed25519
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# Try nacl as alternative
try:
    import nacl.signing
    HAS_NACL = True
except ImportError:
    HAS_NACL = False


def derive_public_key_crypto(private_key_bytes: bytes) -> bytes:
    """Derive Ed25519 public key using cryptography library."""
    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    public_key = private_key.public_key()
    # Get raw 32-byte public key
    public_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return public_bytes


def derive_public_key_nacl(private_key_bytes: bytes) -> bytes:
    """Derive Ed25519 public key using PyNaCl library."""
    signing_key = nacl.signing.SigningKey(private_key_bytes)
    return bytes(signing_key.verify_key)


def blake2b_256(data: bytes) -> bytes:
    """Compute Blake2b-256 hash."""
    return hashlib.blake2b(data, digest_size=32).digest()


def derive_iota_address(tx_key_hex: str, verbose: bool = False) -> str:
    """
    Derive IOTA address from Ed25519 private key.
    
    Args:
        tx_key_hex: Hex-encoded 32-byte Ed25519 private key
        verbose: Print intermediate values
        
    Returns:
        IOTA address as 0x-prefixed hex string
    """
    # Decode private key
    private_key_bytes = bytes.fromhex(tx_key_hex)
    
    if len(private_key_bytes) != 32:
        raise ValueError(f"Invalid private key length: {len(private_key_bytes)} bytes, expected 32")
    
    if verbose:
        print(f"Private key (tx_key_hex): {tx_key_hex}")
        print(f"Private key length: {len(private_key_bytes)} bytes")
    
    # Derive public key
    if HAS_CRYPTO:
        public_key_bytes = derive_public_key_crypto(private_key_bytes)
        if verbose:
            print("Using: cryptography library")
    elif HAS_NACL:
        public_key_bytes = derive_public_key_nacl(private_key_bytes)
        if verbose:
            print("Using: PyNaCl library")
    else:
        raise ImportError(
            "No Ed25519 library available. Install one of:\n"
            "  pip install cryptography\n"
            "  pip install pynacl"
        )
    
    if verbose:
        print(f"Public key: {public_key_bytes.hex()}")
        print(f"Public key length: {len(public_key_bytes)} bytes")
    
    # IOTA Rebased address derivation:
    # Hash public key directly with Blake2b-256 (no flag byte prefix)
    address_bytes = blake2b_256(public_key_bytes)
    
    if verbose:
        print(f"Blake2b-256 hash: {address_bytes.hex()}")
    
    # Format as 0x-prefixed hex
    return f"0x{address_bytes.hex()}"


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Derive IOTA address from issuer_identity.json tx_key_hex"
    )
    parser.add_argument(
        "-f", "--file",
        default="~/.iota-identity-service/issuer_identity.json",
        help="Path to issuer_identity.json"
    )
    parser.add_argument(
        "-k", "--tx-key",
        help="Directly provide tx_key_hex instead of reading from file"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show verbose output with intermediate values"
    )
    
    args = parser.parse_args()
    
    # Get tx_key_hex
    if args.tx_key:
        tx_key_hex = args.tx_key
    else:
        # Read from file
        file_path = Path(args.file).expanduser()
        print(f"Reading from: {file_path}")
        
        if not file_path.exists():
            print(f"Error: File not found: {file_path}")
            sys.exit(1)
        
        with open(file_path) as f:
            identity = json.load(f)
        
        if args.verbose:
            print("\n=== Issuer Identity ===")
            print(f"DID: {identity['did']}")
            print(f"Signing Key: {identity['signing_key_hex'][:16]}...")
            print(f"TX Key: {identity['tx_key_hex']}")
            print(f"VM Fragment: {identity['verification_method_fragment']}")
            print(f"Created: {identity['created_at']}")
        
        tx_key_hex = identity["tx_key_hex"]
    
    print("\n=== Deriving IOTA Address ===")
    if args.verbose:
        print()
    
    try:
        address = derive_iota_address(tx_key_hex, args.verbose)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    print()
    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║ IOTA Address (for faucet funding):                                   ║")
    print(f"║ {address}  ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")
    
    print("\n=== Useful Commands ===")
    print("\n1. Check balance:")
    print(f'''   curl -s -X POST https://api.testnet.iota.cafe \\
     -H "Content-Type: application/json" \\
     -d '{{"jsonrpc":"2.0","id":1,"method":"iotax_getBalance","params":["{address}"]}}' | jq .result''')
    
    print("\n2. Request funds from faucet (gives ~10 IOTA each):")
    print(f'''   curl -s --location --request POST 'https://faucet.testnet.iota.cafe/gas' \\
     --header 'Content-Type: application/json' \\
     --data-raw '{{"FixedAmountRequest":{{"recipient":"{address}"}}}}' | jq .''')


if __name__ == "__main__":
    main()