#!/usr/bin/env python3
"""
IOTA Identity IoT - Parallel Scalability Benchmark

Tests the system's ability to handle concurrent device registrations.
Measures throughput (devices/second) at different concurrency levels.

Usage:
    python3 parallel_benchmark.py                      # Default: 100 devices, 10 concurrent
    python3 parallel_benchmark.py --devices 1000       # Register 1000 devices
    python3 parallel_benchmark.py --concurrency 50     # 50 parallel requests
    python3 parallel_benchmark.py --devices 1000 -c 50 # 1000 devices, 50 concurrent
"""

import argparse
import asyncio
import aiohttp
import time
import json
import random
import string
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional
import statistics

# Default configuration
DEFAULT_IDENTITY_SERVICE = "http://localhost:8080"
DEFAULT_DEVICES = 100
DEFAULT_CONCURRENCY = 10


@dataclass
class RegistrationResult:
    """Result of a single device registration."""
    success: bool
    duration_ms: float
    did: Optional[str] = None
    error: Optional[str] = None


@dataclass
class BenchmarkResult:
    """Aggregated benchmark results."""
    total_devices: int
    successful: int
    failed: int
    concurrency: int
    total_time_seconds: float
    throughput_per_second: float
    min_ms: float
    max_ms: float
    mean_ms: float
    median_ms: float
    p95_ms: float
    p99_ms: float
    std_dev_ms: float


def generate_random_public_key() -> str:
    """Generate a random 64-character hex string (32 bytes)."""
    return ''.join(random.choices('0123456789abcdef', k=64))


def percentile(data: List[float], p: float) -> float:
    """Calculate percentile of sorted data."""
    if not data:
        return 0.0
    sorted_data = sorted(data)
    k = (len(sorted_data) - 1) * (p / 100)
    f = int(k)
    c = f + 1 if f + 1 < len(sorted_data) else f
    return sorted_data[f] + (k - f) * (sorted_data[c] - sorted_data[f])


async def register_device(
    session: aiohttp.ClientSession,
    url: str,
    device_id: int,
    verbose: bool = False
) -> RegistrationResult:
    """Register a single device and measure time."""
    public_key = generate_random_public_key()
    payload = {
        "public_key": public_key,
        "device_type": "sensor",
        "capabilities": [f"benchmark-{device_id}"]
    }
    
    start = time.perf_counter()
    
    try:
        async with session.post(url, json=payload) as response:
            elapsed_ms = (time.perf_counter() - start) * 1000
            
            if response.status == 200:
                data = await response.json()
                did = data.get("did", "unknown")
                if verbose:
                    print(f"  Device {device_id}: ✓ {elapsed_ms:.0f}ms - {did[:50]}...")
                return RegistrationResult(
                    success=True,
                    duration_ms=elapsed_ms,
                    did=did
                )
            else:
                error_text = await response.text()
                if verbose:
                    print(f"  Device {device_id}: ✗ {elapsed_ms:.0f}ms - {error_text[:50]}")
                return RegistrationResult(
                    success=False,
                    duration_ms=elapsed_ms,
                    error=error_text[:100]
                )
    except Exception as e:
        elapsed_ms = (time.perf_counter() - start) * 1000
        if verbose:
            print(f"  Device {device_id}: ✗ {elapsed_ms:.0f}ms - {str(e)[:50]}")
        return RegistrationResult(
            success=False,
            duration_ms=elapsed_ms,
            error=str(e)[:100]
        )


async def run_parallel_benchmark(
    identity_service: str,
    total_devices: int,
    concurrency: int,
    verbose: bool = False
) -> BenchmarkResult:
    """Run parallel device registration benchmark."""
    
    url = f"{identity_service}/api/v1/device/register"
    results: List[RegistrationResult] = []
    
    # Create semaphore to limit concurrency
    semaphore = asyncio.Semaphore(concurrency)
    
    async def limited_register(session: aiohttp.ClientSession, device_id: int):
        async with semaphore:
            return await register_device(session, url, device_id, verbose)
    
    # Create session with connection pooling
    connector = aiohttp.TCPConnector(limit=concurrency + 10)
    timeout = aiohttp.ClientTimeout(total=300)  # 5 min timeout per request
    
    print(f"\n  Starting {total_devices} device registrations with concurrency={concurrency}...")
    print()
    
    overall_start = time.perf_counter()
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        # Create all tasks
        tasks = [
            limited_register(session, i)
            for i in range(total_devices)
        ]
        
        # Run with progress updates
        completed = 0
        batch_size = max(1, total_devices // 20)  # 5% progress updates
        
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            batch_results = await asyncio.gather(*batch)
            results.extend(batch_results)
            completed += len(batch)
            
            # Progress update
            pct = (completed / total_devices) * 100
            successful = sum(1 for r in results if r.success)
            elapsed = time.perf_counter() - overall_start
            rate = completed / elapsed if elapsed > 0 else 0
            print(f"\r  Progress: {completed}/{total_devices} ({pct:.0f}%) - "
                  f"{successful} successful - {rate:.1f} devices/sec", end="", flush=True)
    
    overall_elapsed = time.perf_counter() - overall_start
    print(f"\n\n  Completed in {overall_elapsed:.2f} seconds")
    
    # Calculate statistics
    successful_results = [r for r in results if r.success]
    failed_results = [r for r in results if not r.success]
    
    durations = [r.duration_ms for r in results]
    successful_durations = [r.duration_ms for r in successful_results]
    
    if successful_durations:
        stats_durations = successful_durations
    else:
        stats_durations = durations if durations else [0]
    
    return BenchmarkResult(
        total_devices=total_devices,
        successful=len(successful_results),
        failed=len(failed_results),
        concurrency=concurrency,
        total_time_seconds=overall_elapsed,
        throughput_per_second=total_devices / overall_elapsed if overall_elapsed > 0 else 0,
        min_ms=min(stats_durations),
        max_ms=max(stats_durations),
        mean_ms=statistics.mean(stats_durations),
        median_ms=statistics.median(stats_durations),
        p95_ms=percentile(stats_durations, 95),
        p99_ms=percentile(stats_durations, 99),
        std_dev_ms=statistics.stdev(stats_durations) if len(stats_durations) > 1 else 0
    )


async def check_health(identity_service: str) -> bool:
    """Check if identity service is healthy."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{identity_service}/health") as response:
                return response.status == 200
    except:
        return False


def print_result(result: BenchmarkResult):
    """Print benchmark results in a nice format."""
    print()
    print("=" * 66)
    print("                    BENCHMARK RESULTS")
    print("=" * 66)
    print()
    print(f"  Total Devices:     {result.total_devices}")
    print(f"  Successful:        {result.successful} ({100*result.successful/result.total_devices:.1f}%)")
    print(f"  Failed:            {result.failed}")
    print(f"  Concurrency:       {result.concurrency}")
    print()
    print(f"  Total Time:        {result.total_time_seconds:.2f} seconds")
    print(f"  Throughput:        {result.throughput_per_second:.2f} devices/second")
    print()
    print("  Latency (per device):")
    print(f"    Min:             {result.min_ms:.2f} ms")
    print(f"    Max:             {result.max_ms:.2f} ms")
    print(f"    Mean:            {result.mean_ms:.2f} ms")
    print(f"    Median:          {result.median_ms:.2f} ms")
    print(f"    P95:             {result.p95_ms:.2f} ms")
    print(f"    P99:             {result.p99_ms:.2f} ms")
    print(f"    Std Dev:         {result.std_dev_ms:.2f} ms")
    print()
    print("=" * 66)
    
    # Extrapolations
    print()
    print("  EXTRAPOLATIONS (at current throughput):")
    print()
    rate = result.throughput_per_second
    if rate > 0:
        print(f"    1,000 devices:      {1000/rate:.1f} seconds ({1000/rate/60:.1f} minutes)")
        print(f"    10,000 devices:     {10000/rate:.1f} seconds ({10000/rate/60:.1f} minutes)")
        print(f"    100,000 devices:    {100000/rate/60:.1f} minutes ({100000/rate/3600:.1f} hours)")
        print(f"    1,000,000 devices:  {1000000/rate/3600:.1f} hours ({1000000/rate/86400:.1f} days)")
    print()


async def main():
    parser = argparse.ArgumentParser(
        description="IOTA Identity IoT - Parallel Scalability Benchmark"
    )
    parser.add_argument(
        "--devices", "-d",
        type=int,
        default=DEFAULT_DEVICES,
        help=f"Total number of devices to register (default: {DEFAULT_DEVICES})"
    )
    parser.add_argument(
        "--concurrency", "-c",
        type=int,
        default=DEFAULT_CONCURRENCY,
        help=f"Number of concurrent registrations (default: {DEFAULT_CONCURRENCY})"
    )
    parser.add_argument(
        "--identity-service", "-s",
        default=DEFAULT_IDENTITY_SERVICE,
        help=f"Identity Service URL (default: {DEFAULT_IDENTITY_SERVICE})"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show individual registration results"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file for JSON results"
    )
    
    args = parser.parse_args()
    
    print()
    print("╔════════════════════════════════════════════════════════════════╗")
    print("║     IOTA Identity IoT - Parallel Scalability Benchmark         ║")
    print("╚════════════════════════════════════════════════════════════════╝")
    print()
    print(f"  Identity Service:  {args.identity_service}")
    print(f"  Total Devices:     {args.devices}")
    print(f"  Concurrency:       {args.concurrency}")
    print()
    
    # Check health
    print("  Checking service health...", end=" ")
    if not await check_health(args.identity_service):
        print("FAILED")
        print()
        print("  ERROR: Identity Service is not reachable.")
        print(f"  Make sure it's running at {args.identity_service}")
        return 1
    print("OK")
    
    # Estimate time and cost
    est_time_seq = args.devices * 1.0  # ~1 second per device sequential
    est_time_par = args.devices / args.concurrency * 1.0  # rough estimate
    est_cost = args.devices * 0.009  # ~0.009 IOTA per device
    
    print()
    print("  ESTIMATES:")
    print(f"    Time (sequential): ~{est_time_seq/60:.1f} minutes")
    print(f"    Time (parallel):   ~{est_time_par/60:.1f} minutes (rough estimate)")
    print(f"    Gas cost:          ~{est_cost:.2f} IOTA")
    print()
    
    # Confirm
    try:
        input("  Press Enter to start (Ctrl+C to cancel)... ")
    except KeyboardInterrupt:
        print("\n  Cancelled.")
        return 0
    
    # Run benchmark
    result = await run_parallel_benchmark(
        args.identity_service,
        args.devices,
        args.concurrency,
        args.verbose
    )
    
    # Print results
    print_result(result)
    
    # Save to file if requested
    if args.output:
        output_data = {
            "timestamp": datetime.now().isoformat(),
            "config": {
                "total_devices": args.devices,
                "concurrency": args.concurrency,
                "identity_service": args.identity_service
            },
            "results": {
                "successful": result.successful,
                "failed": result.failed,
                "total_time_seconds": result.total_time_seconds,
                "throughput_per_second": result.throughput_per_second,
                "latency_ms": {
                    "min": result.min_ms,
                    "max": result.max_ms,
                    "mean": result.mean_ms,
                    "median": result.median_ms,
                    "p95": result.p95_ms,
                    "p99": result.p99_ms,
                    "std_dev": result.std_dev_ms
                }
            }
        }
        
        with open(args.output, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"  Results saved to: {args.output}")
        print()
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(asyncio.run(main()))