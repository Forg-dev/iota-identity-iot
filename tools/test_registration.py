#!/usr/bin/env python3
"""
Test di registrazione dispositivi su larga scala.

Uso:
    python3 test_registration.py 100                    # 100 dispositivi
    python3 test_registration.py 10000                  # 10.000 dispositivi
    python3 test_registration.py 1000 --concurrency 10  # 1000 dispositivi, 10 paralleli
    python3 test_registration.py 500 --url http://192.168.1.100:8080
"""
import argparse
import requests
import time
import secrets
import json
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


def generate_keypair_hex():
    """Genera una chiave pubblica Ed25519 fake (32 bytes hex)"""
    return secrets.token_hex(32)


def register_device(args):
    """Registra un singolo dispositivo"""
    device_num, url = args
    public_key = generate_keypair_hex()
    payload = {
        "public_key": public_key,
        "device_type": "sensor",
        "capabilities": ["benchmark"]
    }
    
    start = time.time()
    try:
        response = requests.post(
            f"{url}/api/v1/device/register",
            json=payload,
            timeout=60
        )
        elapsed = time.time() - start
        
        if response.status_code == 200:
            return {"success": True, "latency": elapsed, "device": device_num}
        else:
            return {"success": False, "error": response.text, "device": device_num}
    except Exception as e:
        return {"success": False, "error": str(e), "device": device_num}


def calculate_checkpoint_interval(total):
    """Calcola intervallo checkpoint in base al totale"""
    if total <= 100:
        return 10
    elif total <= 1000:
        return 100
    elif total <= 10000:
        return 500
    else:
        return 1000


def estimate_cost(num_devices):
    """Stima il costo in IOTA"""
    cost_per_did = 0.009
    buffer = 1.2  # 20% buffer
    return num_devices * cost_per_did * buffer


def format_time(seconds):
    """Formatta il tempo in modo leggibile"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f} min"
    else:
        hours = seconds / 3600
        return f"{hours:.1f} ore"


def main():
    parser = argparse.ArgumentParser(
        description="Test di registrazione dispositivi su larga scala",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Esempi:
  python3 test_registration.py 100                     # Test veloce
  python3 test_registration.py 1000                    # Test medio (~17 min)
  python3 test_registration.py 10000                   # Test completo (~3 ore)
  python3 test_registration.py 1000 --concurrency 10   # Più parallelismo
  python3 test_registration.py 100 --dry-run           # Solo stima, no test
        """
    )
    
    parser.add_argument(
        "devices",
        type=int,
        help="Numero di dispositivi da registrare"
    )
    
    parser.add_argument(
        "--url",
        default="http://localhost:8080",
        help="URL dell'Identity Service (default: http://localhost:8080)"
    )
    
    parser.add_argument(
        "--concurrency",
        type=int,
        default=1,
        help="Numero di richieste parallele (default: 1, >1 causa conflitti con single wallet)"
    )
    
    parser.add_argument(
        "--output",
        help="File di output per i risultati JSON (default: auto-generato)"
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Mostra solo le stime senza eseguire il test"
    )
    
    args = parser.parse_args()
    
    # Validazione
    if args.devices < 1:
        print("ERRORE: Il numero di dispositivi deve essere almeno 1")
        sys.exit(1)
    
    if args.concurrency < 1:
        print("ERRORE: La concurrency deve essere almeno 1")
        sys.exit(1)
    
    # Stime
    estimated_time = args.devices * 1.05  # ~1.05 sec per device
    estimated_cost = estimate_cost(args.devices)
    checkpoint_interval = calculate_checkpoint_interval(args.devices)
    
    print("=" * 60)
    print(f"TEST REGISTRAZIONE {args.devices:,} DISPOSITIVI")
    print("=" * 60)
    print()
    print(f"URL:              {args.url}")
    print(f"Concurrency:      {args.concurrency}")
    print(f"Checkpoint ogni:  {checkpoint_interval}")
    print()
    print("--- STIME ---")
    print(f"Tempo stimato:    {format_time(estimated_time)}")
    print(f"IOTA necessari:   ~{estimated_cost:.1f} IOTA (con 20% buffer)")
    print(f"Costo per device: ~0.009 IOTA")
    print()
    
    if args.dry_run:
        print("[DRY RUN] Test non eseguito.")
        sys.exit(0)
    
    # Conferma per test grandi
    if args.devices >= 1000:
        print(f"ATTENZIONE: Stai per registrare {args.devices:,} dispositivi.")
        print(f"Tempo stimato: {format_time(estimated_time)}")
        response = input("Continuare? [y/N] ")
        if response.lower() != 'y':
            print("Test annullato.")
            sys.exit(0)
        print()
    
    # Verifica servizio
    print("Verifica servizio...")
    try:
        health = requests.get(f"{args.url}/health", timeout=5)
        if health.status_code != 200:
            print(f"ERRORE: Identity Service non raggiungibile ({health.status_code})")
            sys.exit(1)
        print(f"  Health: OK")
    except Exception as e:
        print(f"ERRORE: Identity Service non raggiungibile ({e})")
        sys.exit(1)
    
    # Verifica issuer
    try:
        status = requests.get(f"{args.url}/api/v1/issuer/status", timeout=5).json()
        if not status.get("initialized_on_chain"):
            print("ERRORE: Issuer non inizializzato")
            print("Esegui: curl -X POST http://localhost:8080/api/v1/issuer/initialize")
            sys.exit(1)
        if not status.get("has_control"):
            print("ERRORE: Issuer senza controllo (tx_key mancante)")
            sys.exit(1)
        print(f"  Issuer: OK")
        print(f"  DID: {status.get('issuer_did', 'N/A')[:50]}...")
    except Exception as e:
        print(f"ERRORE: Impossibile verificare issuer ({e})")
        sys.exit(1)
    
    print()
    print(f"Inizio: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)
    
    # Statistiche
    results = {
        "success": 0,
        "failed": 0,
        "latencies": [],
        "errors": []
    }
    
    start_time = time.time()
    
    # Esegui test
    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        # Prepara i task
        tasks = [(i, args.url) for i in range(args.devices)]
        futures = {executor.submit(register_device, task): task[0] for task in tasks}
        
        for future in as_completed(futures):
            result = future.result()
            
            if result["success"]:
                results["success"] += 1
                results["latencies"].append(result["latency"])
            else:
                results["failed"] += 1
                if len(results["errors"]) < 100:  # Limita errori salvati
                    results["errors"].append(result["error"])
            
            # Checkpoint
            completed = results["success"] + results["failed"]
            if completed % checkpoint_interval == 0 or completed == args.devices:
                elapsed = time.time() - start_time
                rate = completed / elapsed if elapsed > 0 else 0
                remaining = args.devices - completed
                eta_seconds = remaining / rate if rate > 0 else 0
                
                success_rate = (results["success"] / completed * 100) if completed > 0 else 0
                
                print(f"[{completed:>{len(str(args.devices))}}/{args.devices}] "
                      f"OK: {results['success']} ({success_rate:.1f}%), "
                      f"FAIL: {results['failed']}, "
                      f"Rate: {rate:.2f}/s, "
                      f"ETA: {format_time(eta_seconds)}")
    
    # Risultati finali
    total_time = time.time() - start_time
    
    print("-" * 60)
    print(f"Fine: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    print("=" * 60)
    print("RISULTATI FINALI")
    print("=" * 60)
    print()
    print(f"Dispositivi richiesti:  {args.devices:,}")
    print(f"Successi:               {results['success']:,}")
    print(f"Falliti:                {results['failed']:,}")
    print(f"Success rate:           {results['success']/args.devices*100:.2f}%")
    print()
    print(f"Tempo totale:           {format_time(total_time)}")
    print(f"Throughput effettivo:   {args.devices/total_time:.2f} devices/sec")
    
    if results["latencies"]:
        latencies = sorted(results["latencies"])
        n = len(latencies)
        
        print()
        print("--- LATENZE ---")
        print(f"Min:    {min(latencies)*1000:>8.0f} ms")
        print(f"Max:    {max(latencies)*1000:>8.0f} ms")
        print(f"Mean:   {sum(latencies)/n*1000:>8.0f} ms")
        print(f"Median: {latencies[n//2]*1000:>8.0f} ms")
        print(f"P95:    {latencies[int(n*0.95)]*1000:>8.0f} ms")
        print(f"P99:    {latencies[int(n*0.99)]*1000:>8.0f} ms")
    
    if results["errors"]:
        print()
        print(f"--- ERRORI (primi 5 di {len(results['errors'])}) ---")
        for err in results["errors"][:5]:
            print(f"  - {str(err)[:80]}")
    
    # Salva risultati
    output_file = args.output or f"benchmark_{args.devices}dev_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    output_data = {
        "config": {
            "devices": args.devices,
            "concurrency": args.concurrency,
            "url": args.url,
            "timestamp": datetime.now().isoformat()
        },
        "results": {
            "total": args.devices,
            "success": results["success"],
            "failed": results["failed"],
            "success_rate_percent": results["success"]/args.devices*100,
            "total_time_seconds": total_time,
            "throughput_per_second": args.devices/total_time
        },
        "latencies": {
            "count": len(results["latencies"]),
            "min_ms": min(results["latencies"])*1000 if results["latencies"] else None,
            "max_ms": max(results["latencies"])*1000 if results["latencies"] else None,
            "mean_ms": sum(results["latencies"])/len(results["latencies"])*1000 if results["latencies"] else None,
            "p50_ms": sorted(results["latencies"])[len(results["latencies"])//2]*1000 if results["latencies"] else None,
            "p95_ms": sorted(results["latencies"])[int(len(results["latencies"])*0.95)]*1000 if results["latencies"] else None,
            "p99_ms": sorted(results["latencies"])[int(len(results["latencies"])*0.99)]*1000 if results["latencies"] else None,
        },
        "errors": results["errors"][:20]  # Solo primi 20 errori
    }
    
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print()
    print(f"Risultati salvati in: {output_file}")
    print("=" * 60)


if __name__ == "__main__":
    main()