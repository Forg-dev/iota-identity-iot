#!/usr/bin/env python3
"""
TLS+DID Cold-Cache Benchmark
=============================
Each iteration spawns a NEW client process, so the client's Moka cache
is always empty and every connection forces a blockchain DID resolution.

The server is a persistent process (started once) whose cache warms up
after the first connection.

This measures the worst-case latency: a device connecting to a peer
for the first time (or after a restart).

Usage:
    1. Register server and client devices
    2. Start server:  device-client --data-dir ./server-device server --port 8443
    3. Run this script: python3 benchmark_tls_cold.py --iterations 1000
"""

import argparse
import subprocess
import time
import json
import statistics
import csv
import sys
from datetime import datetime
from pathlib import Path


def parse_metrics(output: str) -> dict | None:
    """Parse the Metrics block from device-client connect output."""
    metrics = {}
    lines = output.strip().split('\n')
    in_metrics = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('Metrics:'):
            in_metrics = True
            continue
        if in_metrics and ':' in stripped:
            key, val = stripped.split(':', 1)
            key = key.strip()
            val = val.strip().rstrip('ms').strip()
            try:
                metrics[key] = float(val)
            except ValueError:
                pass
    if not metrics:
        return None
    return metrics


def run_single_connection(
    binary: str,
    identity_service: str,
    data_dir: str,
    addr: str,
    timeout: int = 30,
) -> dict | None:
    """Run a single client connection and return parsed metrics."""
    cmd = [
        binary,
        '--identity-service', identity_service,
        '--data-dir', data_dir,
        'connect',
        '--addr', addr,
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            return None
        return parse_metrics(result.stdout)
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None


def percentile(data: list, p: float) -> float:
    """Compute the p-th percentile of a sorted list."""
    if not data:
        return 0.0
    k = (len(data) - 1) * (p / 100.0)
    f = int(k)
    c = f + 1
    if c >= len(data):
        return data[f]
    return data[f] + (k - f) * (data[c] - data[f])


def compute_stats(values: list) -> dict:
    """Compute summary statistics for a list of values."""
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
    parser = argparse.ArgumentParser(description='TLS+DID Cold-Cache Benchmark')
    parser.add_argument('--iterations', type=int, default=1000,
                        help='Number of connections (default: 1000)')
    parser.add_argument('--warmup', type=int, default=5,
                        help='Warm-up iterations to skip (default: 5)')
    parser.add_argument('--delay', type=float, default=3.0,
                        help='Delay between connections in seconds (default: 3.0)')
    parser.add_argument('--binary', default='./target/release/device-client',
                        help='Path to device-client binary')
    parser.add_argument('--identity-service', default='http://localhost:8080',
                        help='Identity Service URL')
    parser.add_argument('--client-dir', default='./device-client-data',
                        help='Client data directory')
    parser.add_argument('--addr', default='localhost:8443',
                        help='Server address')
    parser.add_argument('--output', default=None,
                        help='CSV output file (optional)')
    args = parser.parse_args()

    total_iters = args.warmup + args.iterations
    print(f"TLS+DID Cold-Cache Benchmark")
    print(f"  Iterations: {args.iterations} (+ {args.warmup} warm-up)")
    print(f"  Delay: {args.delay}s")
    print(f"  Client dir: {args.client_dir}")
    print(f"  Server addr: {args.addr}")
    print(f"  Started: {datetime.now().isoformat()}")
    print()

    all_metrics = []
    failures = 0

    for i in range(total_iters):
        is_warmup = i < args.warmup
        label = f"[warmup {i+1}/{args.warmup}]" if is_warmup else f"[{i - args.warmup + 1}/{args.iterations}]"

        metrics = run_single_connection(
            args.binary, args.identity_service, args.client_dir, args.addr,
        )

        if metrics is None:
            failures += 1
            print(f"  {label} FAILED")
        else:
            total_ms = metrics.get('Total', metrics.get('DID Auth', 0))
            if not is_warmup:
                all_metrics.append(metrics)
            print(f"  {label} Total: {total_ms:.0f}ms | "
                  f"DID Auth: {metrics.get('DID Auth', 0):.0f}ms | "
                  f"Cred Verify: {metrics.get('Credential Verify', 0):.0f}ms")

        if i < total_iters - 1:
            time.sleep(args.delay)

    # Compute stats
    print(f"\n{'='*70}")
    print(f"RESULTS ({len(all_metrics)} successful / {args.iterations} attempted, "
          f"{failures} failures)")
    print(f"{'='*70}")

    metric_keys = ['TLS Handshake', 'DID Auth', 'Credential Verify',
                   'Challenge-Response', 'Total']

    for key in metric_keys:
        values = [m[key] for m in all_metrics if key in m]
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

    # Export CSV
    if args.output and all_metrics:
        with open(args.output, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['iteration'] + metric_keys)
            writer.writeheader()
            for i, m in enumerate(all_metrics):
                row = {'iteration': i + 1}
                row.update({k: m.get(k, '') for k in metric_keys})
                writer.writerow(row)
        print(f"\nCSV exported to {args.output}")

    print(f"\nFinished: {datetime.now().isoformat()}")


if __name__ == '__main__':
    main()