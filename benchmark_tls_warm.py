#!/usr/bin/env python3
"""
TLS+DID Warm-Cache Benchmark
==============================
This benchmark measures TLS+DID authentication latency when BOTH the
server and client have the issuer's DID Document already in their
local Moka cache.

IMPORTANT: This requires a small modification to the device-client
binary to support repeated connections from the same process.
Specifically, add a --repeat N flag to the 'connect' subcommand.

Without this modification, every client invocation is a new OS process
with an empty cache, which always results in a cold blockchain query.

Option A: Modify device-client (recommended)
---------------------------------------------
Add this to the Connect subcommand in device-client/src/main.rs:

    /// Number of repeated connections (for warm-cache benchmarking)
    #[arg(long, default_value_t = 1)]
    repeat: usize,

    /// Delay between repeated connections in milliseconds
    #[arg(long, default_value_t = 3000)]
    repeat_delay_ms: u64,

Then in handle_connect(), wrap the connection logic in a loop:

    for i in 0..repeat {
        if i > 0 {
            tokio::time::sleep(Duration::from_millis(repeat_delay_ms)).await;
        }
        let connection = client.connect(addr).await?;
        // print metrics for each iteration...
    }

The DIDResolver's Moka cache persists across iterations within the
same process, so iterations 2..N will use cached DID Documents.

Option B: Quick hack with sequential connects from a shell
-----------------------------------------------------------
If you don't want to modify the Rust code, we can approximate the
warm-cache scenario by noting that:
- The SERVER is always warm after the first connection
- The CLIENT always goes to blockchain (new process each time)

The micro-benchmarks already give us the warm-cache numbers:
- Cached DID resolution: 0.13 ms
- Credential verification (cached): 0.24 ms
- Ed25519 sign/verify: < 0.1 ms
- Total projected warm: < 1 ms

So the warm-cache benchmark is really about measuring this directly
rather than projecting it.

Usage (after implementing Option A):
    1. Register server and client devices
    2. Start server:  device-client --data-dir ./server-device server --port 8443
    3. Run client with repeat:
       device-client --data-dir ./client-device connect --addr localhost:8443 \\
           --repeat 100 --repeat-delay-ms 1000

The output should show:
  - Iteration 1: ~233 ms (cold, blockchain query)
  - Iterations 2-100: < 5 ms (warm, cached DID Documents)
"""

import argparse
import subprocess
import time
import re
import statistics
import csv
import sys
from datetime import datetime


def parse_repeated_metrics(output: str) -> list[dict]:
    """
    Parse metrics from a device-client run with --repeat N.

    Expected output format per iteration:
        [1/100] Connected and authenticated!
          Peer DID: did:iota:testnet:0x...
          Metrics:
            TLS Handshake: 0ms
            DID Auth: 233ms
            Credential Verify: 74ms
            Challenge-Response: 0ms
            Total: 234ms

        [2/100] Connected and authenticated!
          Metrics:
            TLS Handshake: 0ms
            DID Auth: 1ms
            ...
    """
    iterations = []
    current_metrics = {}
    in_metrics = False

    for line in output.strip().split('\n'):
        stripped = line.strip()

        # New iteration marker
        if re.match(r'\[\d+/\d+\]', stripped):
            if current_metrics:
                iterations.append(current_metrics)
                current_metrics = {}
            in_metrics = False
            continue

        if stripped.startswith('Metrics:'):
            in_metrics = True
            continue

        if in_metrics and ':' in stripped:
            key, val = stripped.split(':', 1)
            key = key.strip()
            val = val.strip().rstrip('ms').strip()
            try:
                current_metrics[key] = float(val)
            except ValueError:
                pass

    # Don't forget the last iteration
    if current_metrics:
        iterations.append(current_metrics)

    return iterations


def percentile(data: list, p: float) -> float:
    if not data:
        return 0.0
    k = (len(data) - 1) * (p / 100.0)
    f = int(k)
    c = f + 1
    if c >= len(data):
        return data[f]
    return data[f] + (k - f) * (data[c] - data[f])


def compute_stats(values: list) -> dict:
    if not values:
        return {}
    s = sorted(values)
    return {
        'n': len(s),
        'min': min(s),
        'max': max(s),
        'mean': statistics.mean(s),
        'median': statistics.median(s),
        'p95': percentile(s, 95),
        'p99': percentile(s, 99),
        'std_dev': statistics.stdev(s) if len(s) > 1 else 0.0,
    }


def main():
    parser = argparse.ArgumentParser(description='TLS+DID Warm-Cache Benchmark')
    parser.add_argument('--repeat', type=int, default=100,
                        help='Number of connections from same process (default: 100)')
    parser.add_argument('--repeat-delay-ms', type=int, default=1000,
                        help='Delay between connections in ms (default: 1000)')
    parser.add_argument('--warmup', type=int, default=1,
                        help='Skip first N iterations as warm-up (default: 1)')
    parser.add_argument('--binary', default='./target/release/device-client',
                        help='Path to device-client binary')
    parser.add_argument('--identity-service', default='http://localhost:8080')
    parser.add_argument('--client-dir', default='./device-client-data')
    parser.add_argument('--addr', default='localhost:8443')
    parser.add_argument('--output', default=None, help='CSV output file')
    args = parser.parse_args()

    print(f"TLS+DID Warm-Cache Benchmark")
    print(f"  Repeat: {args.repeat} connections from same process")
    print(f"  Delay: {args.repeat_delay_ms} ms")
    print(f"  Warm-up: skip first {args.warmup} iterations")
    print(f"  Started: {datetime.now().isoformat()}")
    print()

    cmd = [
        args.binary,
        '--identity-service', args.identity_service,
        '--data-dir', args.client_dir,
        'connect',
        '--addr', args.addr,
        '--repeat', str(args.repeat),
        '--repeat-delay-ms', str(args.repeat_delay_ms),
    ]

    print(f"Running: {' '.join(cmd)}")
    print()

    total_timeout = args.repeat * (args.repeat_delay_ms / 1000 + 10) + 60
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=total_timeout,
        )
    except subprocess.TimeoutExpired:
        print("ERROR: Process timed out")
        sys.exit(1)

    # Combine stdout and stderr (tracing INFO goes to stderr)
    combined_output = (result.stdout or '') + '\n' + (result.stderr or '')

    if result.returncode != 0:
        print(f"ERROR: Process exited with code {result.returncode}")
        print(combined_output[-2000:])
        sys.exit(1)

    # Parse all iterations from combined output
    all_metrics = parse_repeated_metrics(combined_output)
    print(f"Parsed {len(all_metrics)} iterations from output")

    # Skip warm-up
    measured = all_metrics[args.warmup:]
    skipped = all_metrics[:args.warmup]

    if skipped:
        first = skipped[0]
        print(f"\nWarm-up iteration (cold cache):")
        print(f"  Total: {first.get('Total', '?')} ms (includes blockchain resolution)")

    # Compute stats for warm iterations
    print(f"\n{'=' * 70}")
    print(f"WARM-CACHE RESULTS ({len(measured)} iterations)")
    print(f"{'=' * 70}")

    metric_keys = ['TLS Handshake', 'DID Auth', 'Credential Verify',
                   'Challenge-Response', 'Total']

    for key in metric_keys:
        values = [m[key] for m in measured if key in m]
        if not values:
            continue
        stats = compute_stats(values)
        print(f"\n  {key}:")
        print(f"    Min: {stats['min']:.2f} ms")
        print(f"    Max: {stats['max']:.2f} ms")
        print(f"    Mean: {stats['mean']:.2f} ms")
        print(f"    Median: {stats['median']:.2f} ms")
        print(f"    P95: {stats['p95']:.2f} ms")
        print(f"    P99: {stats['p99']:.2f} ms")
        print(f"    Std Dev: {stats['std_dev']:.2f} ms")

    # CSV export
    if args.output and measured:
        with open(args.output, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['iteration', 'type'] + metric_keys)
            writer.writeheader()
            for i, m in enumerate(all_metrics):
                row = {
                    'iteration': i + 1,
                    'type': 'warmup' if i < args.warmup else 'measured',
                }
                row.update({k: m.get(k, '') for k in metric_keys})
                writer.writerow(row)
        print(f"\nCSV exported to {args.output}")

    print(f"\nFinished: {datetime.now().isoformat()}")


if __name__ == '__main__':
    main()