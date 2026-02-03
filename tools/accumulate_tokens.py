#!/usr/bin/env python3
"""
IOTA Testnet Faucet Accumulator

Automatically requests tokens from the IOTA testnet faucet,
managing cooldowns and tracking progress toward a target balance.

Usage:
    python3 accumulate_tokens.py                    # Use default address from issuer_identity.json
    python3 accumulate_tokens.py --target 200       # Accumulate until 200 IOTA
    python3 accumulate_tokens.py --address 0x...    # Use specific address
    python3 accumulate_tokens.py --requests 20      # Make exactly 20 requests
"""

import argparse
import json
import time
import sys
from pathlib import Path
from datetime import datetime, timedelta

try:
    import requests
except ImportError:
    print("ERROR: 'requests' library not found. Install with: pip install requests")
    sys.exit(1)

# Constants
FAUCET_URL = "https://faucet.testnet.iota.cafe/gas"
RPC_URL = "https://api.testnet.iota.cafe"
NANOS_PER_IOTA = 1_000_000_000
DEFAULT_ISSUER_FILE = Path.home() / ".iota-identity-service" / "issuer_identity.json"

# Faucet gives ~1 IOTA per request, cooldown is ~60 seconds
TOKENS_PER_REQUEST = 1.0  # IOTA
COOLDOWN_SECONDS = 65  # Add buffer to be safe
DEFAULT_TARGET_IOTA = 100


def get_balance(address: str) -> tuple[float, int]:
    """Get balance for an address. Returns (balance_iota, coin_count)."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "iotax_getBalance",
        "params": [address]
    }
    
    try:
        response = requests.post(RPC_URL, json=payload, timeout=30)
        response.raise_for_status()
        result = response.json().get("result", {})
        total_balance = int(result.get("totalBalance", 0))
        coin_count = result.get("coinObjectCount", 0)
        return total_balance / NANOS_PER_IOTA, coin_count
    except Exception as e:
        print(f"    Error checking balance: {e}")
        return -1, 0


def request_faucet(address: str) -> tuple[bool, str]:
    """Request tokens from faucet. Returns (success, message)."""
    payload = {
        "FixedAmountRequest": {
            "recipient": address
        }
    }
    
    try:
        response = requests.post(
            FAUCET_URL,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=30
        )
        
        if response.status_code == 200:
            return True, "Success"
        elif response.status_code == 429:
            return False, "Rate limited - waiting for cooldown"
        else:
            return False, f"HTTP {response.status_code}: {response.text[:100]}"
    except requests.exceptions.Timeout:
        return False, "Request timeout"
    except Exception as e:
        return False, str(e)


def derive_address_from_issuer_file(filepath: Path) -> str:
    """Derive IOTA address from issuer_identity.json tx_key_hex."""
    try:
        from hashlib import blake2b
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        print("ERROR: Required libraries not found. Install with:")
        print("  pip install cryptography")
        sys.exit(1)
    
    with open(filepath) as f:
        data = json.load(f)
    
    tx_key_hex = data.get("tx_key_hex")
    if not tx_key_hex:
        raise ValueError("No tx_key_hex found in issuer_identity.json")
    
    # Derive public key
    private_key_bytes = bytes.fromhex(tx_key_hex)
    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    public_key_bytes = private_key.public_key().public_bytes_raw()
    
    # Hash with Blake2b-256 (no flag byte)
    address_bytes = blake2b(public_key_bytes, digest_size=32).digest()
    
    return f"0x{address_bytes.hex()}"


def format_duration(seconds: int) -> str:
    """Format seconds as human-readable duration."""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    else:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours}h {minutes}m"


def print_progress_bar(current: float, target: float, width: int = 40):
    """Print a progress bar."""
    if target <= 0:
        return
    
    progress = min(current / target, 1.0)
    filled = int(width * progress)
    bar = "█" * filled + "░" * (width - filled)
    percentage = progress * 100
    
    print(f"  [{bar}] {percentage:.1f}% ({current:.2f}/{target:.0f} IOTA)")


def main():
    parser = argparse.ArgumentParser(
        description="Accumulate IOTA tokens from testnet faucet"
    )
    parser.add_argument(
        "--address", "-a",
        help="IOTA address to fund (default: derived from issuer_identity.json)"
    )
    parser.add_argument(
        "--target", "-t",
        type=float,
        default=DEFAULT_TARGET_IOTA,
        help=f"Target balance in IOTA (default: {DEFAULT_TARGET_IOTA})"
    )
    parser.add_argument(
        "--requests", "-r",
        type=int,
        help="Make exactly N requests (ignores --target)"
    )
    parser.add_argument(
        "--cooldown", "-c",
        type=int,
        default=COOLDOWN_SECONDS,
        help=f"Seconds between requests (default: {COOLDOWN_SECONDS})"
    )
    parser.add_argument(
        "--file", "-f",
        type=Path,
        default=DEFAULT_ISSUER_FILE,
        help="Path to issuer_identity.json"
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Minimal output"
    )
    
    args = parser.parse_args()
    
    # Get address
    if args.address:
        address = args.address
        if not address.startswith("0x"):
            address = f"0x{address}"
    else:
        if not args.file.exists():
            print(f"ERROR: Issuer identity file not found: {args.file}")
            print("Either provide --address or ensure the issuer service has been initialized.")
            sys.exit(1)
        
        address = derive_address_from_issuer_file(args.file)
    
    # Print header
    print()
    print("╔════════════════════════════════════════════════════════════════╗")
    print("║           IOTA Testnet Token Accumulator                       ║")
    print("╚════════════════════════════════════════════════════════════════╝")
    print()
    print(f"  Address: {address}")
    print(f"  Faucet:  {FAUCET_URL}")
    print(f"  Cooldown: {args.cooldown} seconds between requests")
    print()
    
    # Check initial balance
    initial_balance, coin_count = get_balance(address)
    if initial_balance < 0:
        print("ERROR: Could not check initial balance")
        sys.exit(1)
    
    print(f"  Initial balance: {initial_balance:.4f} IOTA ({coin_count} coins)")
    
    # Determine mode
    if args.requests:
        mode = "requests"
        total_requests = args.requests
        print(f"  Mode: Make exactly {total_requests} requests")
    else:
        mode = "target"
        target = args.target
        if initial_balance >= target:
            print(f"\n Already at target! Balance: {initial_balance:.4f} IOTA >= {target:.0f} IOTA")
            sys.exit(0)
        
        remaining = target - initial_balance
        estimated_requests = int(remaining / TOKENS_PER_REQUEST) + 1
        estimated_time = estimated_requests * args.cooldown
        
        print(f"  Target: {target:.0f} IOTA")
        print(f"  Needed: ~{remaining:.2f} IOTA ({estimated_requests} requests)")
        print(f"  Est. time: {format_duration(estimated_time)}")
    
    print()
    print("─" * 66)
    print()
    
    # Confirm
    if not args.quiet:
        try:
            input("Press Enter to start (Ctrl+C to cancel)... ")
        except KeyboardInterrupt:
            print("\nCancelled.")
            sys.exit(0)
    
    print()
    
    # Main loop
    request_count = 0
    success_count = 0
    start_time = time.time()
    current_balance = initial_balance
    
    try:
        while True:
            # Check if we should stop
            if mode == "requests" and request_count >= total_requests:
                break
            if mode == "target" and current_balance >= target:
                break
            
            request_count += 1
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            # Make request
            if not args.quiet:
                print(f"[{timestamp}] Request #{request_count}...", end=" ", flush=True)
            
            success, message = request_faucet(address)
            
            if success:
                success_count += 1
                if not args.quiet:
                    print(f" {message}")
                
                # Wait a moment for transaction to process
                time.sleep(3)
                
                # Check new balance
                new_balance, coin_count = get_balance(address)
                if new_balance >= 0:
                    gained = new_balance - current_balance
                    current_balance = new_balance
                    if not args.quiet:
                        print(f"           Balance: {current_balance:.4f} IOTA (+{gained:.4f})")
                        if mode == "target":
                            print_progress_bar(current_balance, target)
            else:
                if not args.quiet:
                    print(f"⏳ {message}")
            
            # Check if we're done
            if mode == "requests" and request_count >= total_requests:
                break
            if mode == "target" and current_balance >= target:
                break
            
            # Cooldown with countdown
            if not args.quiet:
                print(f"           Waiting {args.cooldown}s for cooldown...", end="", flush=True)
                for remaining in range(args.cooldown, 0, -1):
                    print(f"\r           Waiting {remaining}s for cooldown...  ", end="", flush=True)
                    time.sleep(1)
                print("\r           " + " " * 40 + "\r", end="")
            else:
                time.sleep(args.cooldown)
            
            print()
    
    except KeyboardInterrupt:
        print("\n\n  Interrupted by user")
    
    # Final summary
    elapsed = time.time() - start_time
    final_balance, coin_count = get_balance(address)
    if final_balance < 0:
        final_balance = current_balance
    
    total_gained = final_balance - initial_balance
    
    print()
    print("═" * 66)
    print()
    print("                        SUMMARY")
    print()
    print(f"  Requests made:    {request_count}")
    print(f"  Successful:       {success_count}")
    print(f"  Time elapsed:     {format_duration(int(elapsed))}")
    print()
    print(f"  Initial balance:  {initial_balance:.4f} IOTA")
    print(f"  Final balance:    {final_balance:.4f} IOTA")
    print(f"  Total gained:     {total_gained:.4f} IOTA")
    print(f"  Coin objects:     {coin_count}")
    print()
    
    if mode == "target":
        if final_balance >= target:
            print(f"   Target reached! ({final_balance:.2f} >= {target:.0f} IOTA)")
        else:
            print(f"    Target not reached ({final_balance:.2f} < {target:.0f} IOTA)")
    
    print()
    print("═" * 66)
    print()


if __name__ == "__main__":
    main()