//! # IOTA Identity IoT - Benchmark Suite
//!
//! This benchmark suite measures the performance of the decentralized identity system
//! and compares it against traditional PKI baselines where applicable.
//!
//! ## Benchmarks Included
//!
//! 1. DID Creation - Time to create a new DID on the blockchain
//! 2. DID Resolution - Time to resolve a DID (cold vs cached)
//! 3. Credential Issuance - Time to issue a Verifiable Credential
//! 4. Credential Verification - Time to verify a credential locally
//! 5. Revocation Check - Time to check if a credential is revoked
//! 6. TLS + DID Authentication - Full mutual authentication time
//!
//! ## Usage
//!
//! ```bash
//! # Run all benchmarks (requires Identity Service running)
//! cargo run --release --package benchmarks -- --all
//!
//! # Run specific benchmark
//! cargo run --release --package benchmarks -- --benchmark did-resolution
//!
//! # Export results to CSV
//! cargo run --release --package benchmarks -- --all --output results.csv
//! ```

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, ValueEnum};
use hdrhistogram::Histogram;
use reqwest::Client;
use serde::Serialize;
use std::time::Instant;
use tracing::info;

// Default Identity Service URL
const DEFAULT_IDENTITY_SERVICE: &str = "http://localhost:8080";

// Number of iterations for each benchmark
const DEFAULT_ITERATIONS: usize = 10;

// Warm-up iterations (not counted in results)
const WARMUP_ITERATIONS: usize = 2;

#[derive(Parser, Debug)]
#[command(name = "benchmark")]
#[command(about = "IOTA Identity IoT Benchmark Suite")]
struct Args {
    /// Run all benchmarks
    #[arg(long)]
    all: bool,

    /// Specific benchmark to run
    #[arg(long, value_enum)]
    benchmark: Option<BenchmarkType>,

    /// Number of iterations per benchmark
    #[arg(long, default_value_t = DEFAULT_ITERATIONS)]
    iterations: usize,

    /// Identity Service URL
    #[arg(long, default_value = DEFAULT_IDENTITY_SERVICE)]
    identity_service: String,

    /// Output file for CSV results
    #[arg(long)]
    output: Option<String>,

    /// Skip warm-up iterations
    #[arg(long)]
    no_warmup: bool,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BenchmarkType {
    DidCreation,
    DidResolution,
    DidResolutionCached,
    CredentialIssuance,
    CredentialVerification,
    RevocationCheck,
    TlsAuthentication,
}

#[derive(Debug, Clone, Serialize)]
struct BenchmarkResult {
    name: String,
    iterations: usize,
    min_ms: f64,
    max_ms: f64,
    mean_ms: f64,
    median_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    std_dev_ms: f64,
    timestamp: DateTime<Utc>,
}

impl BenchmarkResult {
    fn from_histogram(name: &str, histogram: &Histogram<u64>, iterations: usize) -> Self {
        let to_ms = |v: u64| v as f64 / 1000.0; // microseconds to milliseconds
        
        Self {
            name: name.to_string(),
            iterations,
            min_ms: to_ms(histogram.min()),
            max_ms: to_ms(histogram.max()),
            mean_ms: histogram.mean() / 1000.0,
            median_ms: to_ms(histogram.value_at_quantile(0.5)),
            p95_ms: to_ms(histogram.value_at_quantile(0.95)),
            p99_ms: to_ms(histogram.value_at_quantile(0.99)),
            std_dev_ms: histogram.stdev() / 1000.0,
            timestamp: Utc::now(),
        }
    }

    fn print_report(&self) {
        println!("\n{}", "=".repeat(60));
        println!("Benchmark: {}", self.name);
        println!("{}", "=".repeat(60));
        println!("Iterations: {}", self.iterations);
        println!();
        println!("  Min:      {:>10.2} ms", self.min_ms);
        println!("  Max:      {:>10.2} ms", self.max_ms);
        println!("  Mean:     {:>10.2} ms", self.mean_ms);
        println!("  Median:   {:>10.2} ms", self.median_ms);
        println!("  P95:      {:>10.2} ms", self.p95_ms);
        println!("  P99:      {:>10.2} ms", self.p99_ms);
        println!("  Std Dev:  {:>10.2} ms", self.std_dev_ms);
        println!("{}", "=".repeat(60));
    }
}

struct BenchmarkRunner {
    client: Client,
    identity_service: String,
    iterations: usize,
    warmup: bool,
    verbose: bool,
}

impl BenchmarkRunner {
    fn new(identity_service: String, iterations: usize, warmup: bool, verbose: bool) -> Self {
        Self {
            client: Client::new(),
            identity_service,
            iterations,
            warmup,
            verbose,
        }
    }

    async fn check_service_health(&self) -> Result<()> {
        let url = format!("{}/health", self.identity_service);
        let response = self.client.get(&url).send().await?;
        
        if !response.status().is_success() {
            anyhow::bail!("Identity Service is not healthy. Make sure it's running at {}", self.identity_service);
        }
        
        info!("Identity Service is healthy");
        Ok(())
    }

    fn create_histogram() -> Histogram<u64> {
        // Histogram with microsecond precision, max 60 seconds
        Histogram::new_with_bounds(1, 60_000_000, 3).unwrap()
    }

    async fn run_benchmark<F, Fut>(&self, name: &str, mut f: F) -> Result<BenchmarkResult>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        let mut histogram = Self::create_histogram();

        // Warm-up phase
        if self.warmup {
            if self.verbose {
                println!("  Warming up ({} iterations)...", WARMUP_ITERATIONS);
            }
            for _ in 0..WARMUP_ITERATIONS {
                f().await?;
            }
        }

        // Measurement phase
        if self.verbose {
            println!("  Running {} iterations...", self.iterations);
        }

        for i in 0..self.iterations {
            let start = Instant::now();
            f().await?;
            let elapsed = start.elapsed();
            
            let micros = elapsed.as_micros() as u64;
            histogram.record(micros).ok();
            
            if self.verbose {
                println!("    Iteration {}: {:.2} ms", i + 1, elapsed.as_secs_f64() * 1000.0);
            }
        }

        Ok(BenchmarkResult::from_histogram(name, &histogram, self.iterations))
    }

    // =========================================================================
    // BENCHMARK: DID Creation
    // =========================================================================
    
    async fn benchmark_did_creation(&self) -> Result<BenchmarkResult> {
        println!("\nBenchmark: DID Creation (via Device Registration)");
        println!("  This measures the time to create a new DID on the blockchain.");
        println!("  Expected: ~7 seconds (includes blockchain transaction)");

        self.run_benchmark("DID Creation", || {
            let client = self.client.clone();
            let url = format!("{}/api/v1/device/register", self.identity_service);
            
            async move {
                let public_key = Self::generate_random_public_key();
                
                let response = client
                    .post(&url)
                    .json(&serde_json::json!({
                        "public_key": public_key,
                        "device_type": "sensor",
                        "capabilities": ["benchmark"]
                    }))
                    .send()
                    .await?;
                
                if !response.status().is_success() {
                    let error_text = response.text().await.unwrap_or_default();
                    anyhow::bail!("DID creation failed: {}", error_text);
                }
                
                Ok(())
            }
        }).await
    }

    // =========================================================================
    // BENCHMARK: DID Resolution (Cold)
    // =========================================================================
    
    async fn benchmark_did_resolution_cold(&self) -> Result<BenchmarkResult> {
        println!("\nBenchmark: DID Resolution (Cold Cache)");
        println!("  This measures the time to resolve a DID with empty cache.");
        println!("  Expected: ~150-200ms (blockchain query)");

        // First, register a device to get a DID
        let public_key = Self::generate_random_public_key();
        let register_response: serde_json::Value = self.client
            .post(&format!("{}/api/v1/device/register", self.identity_service))
            .json(&serde_json::json!({
                "public_key": public_key,
                "device_type": "sensor",
                "capabilities": ["benchmark"]
            }))
            .send()
            .await?
            .json()
            .await?;
        
        let did = register_response["did"].as_str()
            .context("Missing DID in response")?
            .to_string();

        // Clear cache before benchmark
        let _ = self.client
            .post(&format!("{}/api/v1/admin/cache/clear", self.identity_service))
            .send()
            .await;

        self.run_benchmark("DID Resolution (Cold)", || {
            let did = did.clone();
            let client = self.client.clone();
            let identity_service = self.identity_service.clone();
            
            async move {
                // Clear cache before each resolution
                let _ = client.post(&format!("{}/api/v1/admin/cache/clear", identity_service))
                    .send()
                    .await;
                
                let url = format!("{}/api/v1/did/resolve/{}", identity_service, did);
                let response = client.get(&url).send().await?;
                
                if !response.status().is_success() {
                    let error_text = response.text().await.unwrap_or_default();
                    anyhow::bail!("DID resolution failed: {}", error_text);
                }
                
                Ok(())
            }
        }).await
    }

    // =========================================================================
    // BENCHMARK: DID Resolution (Cached)
    // =========================================================================
    
    async fn benchmark_did_resolution_cached(&self) -> Result<BenchmarkResult> {
        println!("\nBenchmark: DID Resolution (Cached)");
        println!("  This measures the time to resolve a DID from cache.");
        println!("  Expected: <1ms");

        // First, register a device to get a DID
        let public_key = Self::generate_random_public_key();
        let register_response: serde_json::Value = self.client
            .post(&format!("{}/api/v1/device/register", self.identity_service))
            .json(&serde_json::json!({
                "public_key": public_key,
                "device_type": "sensor",
                "capabilities": ["benchmark"]
            }))
            .send()
            .await?
            .json()
            .await?;
        
        let did = register_response["did"].as_str()
            .context("Missing DID in response")?
            .to_string();

        // Prime the cache by resolving once
        let _ = self.client
            .get(&format!("{}/api/v1/did/resolve/{}", self.identity_service, did))
            .send()
            .await;

        self.run_benchmark("DID Resolution (Cached)", || {
            let did = did.clone();
            let client = self.client.clone();
            let url = format!("{}/api/v1/did/resolve/{}", self.identity_service, did);
            
            async move {
                let response = client.get(&url).send().await?;
                
                if !response.status().is_success() {
                    let error_text = response.text().await.unwrap_or_default();
                    anyhow::bail!("DID resolution failed: {}", error_text);
                }
                
                Ok(())
            }
        }).await
    }

    // =========================================================================
    // BENCHMARK: Credential Issuance
    // =========================================================================
    
    async fn benchmark_credential_issuance(&self) -> Result<BenchmarkResult> {
        println!("\nBenchmark: Credential Issuance (via Device Registration)");
        println!("  This measures the time to register a device and issue a credential.");
        println!("  Note: This includes DID creation, so timing reflects full registration.");
        println!("  The credential issuance itself is <5ms but is bundled with DID creation.");

        self.run_benchmark("Credential Issuance", || {
            let client = self.client.clone();
            let url = format!("{}/api/v1/device/register", self.identity_service);
            
            async move {
                let public_key = Self::generate_random_public_key();
                
                let response = client
                    .post(&url)
                    .json(&serde_json::json!({
                        "public_key": public_key,
                        "device_type": "sensor",
                        "capabilities": ["temperature"]
                    }))
                    .send()
                    .await?;
                
                if !response.status().is_success() {
                    let error_text = response.text().await.unwrap_or_default();
                    anyhow::bail!("Credential issuance failed: {}", error_text);
                }
                
                Ok(())
            }
        }).await
    }

    // =========================================================================
    // BENCHMARK: Credential Verification
    // =========================================================================
    
    async fn benchmark_credential_verification(&self) -> Result<BenchmarkResult> {
        println!("\nBenchmark: Credential Verification");
        println!("  This measures the time to verify a credential.");
        println!("  Expected: <5ms (with cached issuer DID)");

        // First, create a device and get its credential
        let public_key = Self::generate_random_public_key();
        let register_response: serde_json::Value = self.client
            .post(&format!("{}/api/v1/device/register", self.identity_service))
            .json(&serde_json::json!({
                "public_key": public_key,
                "device_type": "sensor",
                "capabilities": ["temperature"]
            }))
            .send()
            .await?
            .json()
            .await?;
        
        let credential_jwt = register_response["credential_jwt"].as_str()
            .context("Missing credential_jwt in response")?
            .to_string();

        self.run_benchmark("Credential Verification", || {
            let credential_jwt = credential_jwt.clone();
            let client = self.client.clone();
            let url = format!("{}/api/v1/credential/verify", self.identity_service);
            
            async move {
                let response = client
                    .post(&url)
                    .json(&serde_json::json!({
                        "credential_jwt": credential_jwt
                    }))
                    .send()
                    .await?;
                
                if !response.status().is_success() {
                    anyhow::bail!("Credential verification failed");
                }
                
                Ok(())
            }
        }).await
    }

    // =========================================================================
    // BENCHMARK: Revocation Check
    // =========================================================================
    
    async fn benchmark_revocation_check(&self) -> Result<BenchmarkResult> {
        println!("\nBenchmark: Revocation Check");
        println!("  This measures the time to check if a credential is revoked.");
        println!("  Expected: <1ms (bitmap lookup)");

        // We'll check a revocation index that exists
        // First register a device to ensure we have at least one credential
        let public_key = Self::generate_random_public_key();
        self.client
            .post(&format!("{}/api/v1/device/register", self.identity_service))
            .json(&serde_json::json!({
                "public_key": public_key,
                "device_type": "sensor"
            }))
            .send()
            .await?;

        self.run_benchmark("Revocation Check", || {
            let client = self.client.clone();
            // Check index 0 (first credential)
            let url = format!("{}/api/v1/credential/status-onchain/0", self.identity_service);
            
            async move {
                let response = client.get(&url).send().await?;
                
                if !response.status().is_success() {
                    anyhow::bail!("Revocation check failed");
                }
                
                Ok(())
            }
        }).await
    }

    // =========================================================================
    // BENCHMARK: Full Device Registration
    // =========================================================================
    
    async fn benchmark_device_registration(&self) -> Result<BenchmarkResult> {
        println!("\nBenchmark: Full Device Registration");
        println!("  This measures the complete registration flow (DID + Credential).");
        println!("  Expected: ~7 seconds (dominated by blockchain transaction)");

        self.run_benchmark("Device Registration", || {
            let client = self.client.clone();
            let url = format!("{}/api/v1/device/register", self.identity_service);
            
            async move {
                let public_key = Self::generate_random_public_key();
                
                let response = client
                    .post(&url)
                    .json(&serde_json::json!({
                        "public_key": public_key,
                        "device_type": "sensor",
                        "capabilities": ["temperature", "humidity"]
                    }))
                    .send()
                    .await?;
                
                if !response.status().is_success() {
                    let error_text = response.text().await.unwrap_or_default();
                    anyhow::bail!("Device registration failed: {}", error_text);
                }
                
                Ok(())
            }
        }).await
    }

    // =========================================================================
    // Helper Functions
    // =========================================================================
    
    fn generate_random_public_key() -> String {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        hex::encode(verifying_key.as_bytes())
    }
}

// =============================================================================
// CSV Export
// =============================================================================

fn export_to_csv(results: &[BenchmarkResult], filename: &str) -> Result<()> {
    use std::fs::File;
    use std::io::Write;

    let mut file = File::create(filename)?;
    
    // Header
    writeln!(file, "benchmark,iterations,min_ms,max_ms,mean_ms,median_ms,p95_ms,p99_ms,std_dev_ms,timestamp")?;
    
    // Data rows
    for r in results {
        writeln!(
            file,
            "{},{},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{}",
            r.name,
            r.iterations,
            r.min_ms,
            r.max_ms,
            r.mean_ms,
            r.median_ms,
            r.p95_ms,
            r.p99_ms,
            r.std_dev_ms,
            r.timestamp.to_rfc3339()
        )?;
    }
    
    println!("\nResults exported to: {}", filename);
    Ok(())
}

// =============================================================================
// Main
// =============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Setup logging
    let log_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(log_level)
        .init();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║       IOTA Identity IoT - Benchmark Suite                  ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();
    println!("Configuration:");
    println!("  Identity Service: {}", args.identity_service);
    println!("  Iterations: {}", args.iterations);
    println!("  Warm-up: {}", if args.no_warmup { "disabled" } else { "enabled" });
    println!();

    let runner = BenchmarkRunner::new(
        args.identity_service.clone(),
        args.iterations,
        !args.no_warmup,
        args.verbose,
    );

    // Check service health
    runner.check_service_health().await
        .context("Failed to connect to Identity Service. Is it running?")?;

    let mut results: Vec<BenchmarkResult> = Vec::new();

    // Run benchmarks based on arguments
    if args.all {
        // Run all benchmarks
        println!("\n>>> Running all benchmarks...\n");

        // Note: DID Creation and Device Registration are slow (~7s each)
        // so we run fewer iterations for those

        // Fast benchmarks (many iterations)
        results.push(runner.benchmark_did_resolution_cached().await?);
        results.last().unwrap().print_report();

        results.push(runner.benchmark_credential_issuance().await?);
        results.last().unwrap().print_report();

        results.push(runner.benchmark_credential_verification().await?);
        results.last().unwrap().print_report();

        results.push(runner.benchmark_revocation_check().await?);
        results.last().unwrap().print_report();

        // Slow benchmarks (fewer iterations, just for reference)
        println!("\n>>> Running slow benchmarks (fewer iterations)...\n");
        
        let slow_runner = BenchmarkRunner::new(
            args.identity_service.clone(),
            3, // Only 3 iterations for slow benchmarks
            !args.no_warmup,
            args.verbose,
        );

        results.push(slow_runner.benchmark_did_resolution_cold().await?);
        results.last().unwrap().print_report();

        results.push(slow_runner.benchmark_did_creation().await?);
        results.last().unwrap().print_report();

        results.push(slow_runner.benchmark_device_registration().await?);
        results.last().unwrap().print_report();

    } else if let Some(benchmark) = args.benchmark {
        // Run specific benchmark
        let result = match benchmark {
            BenchmarkType::DidCreation => runner.benchmark_did_creation().await?,
            BenchmarkType::DidResolution => runner.benchmark_did_resolution_cold().await?,
            BenchmarkType::DidResolutionCached => runner.benchmark_did_resolution_cached().await?,
            BenchmarkType::CredentialIssuance => runner.benchmark_credential_issuance().await?,
            BenchmarkType::CredentialVerification => runner.benchmark_credential_verification().await?,
            BenchmarkType::RevocationCheck => runner.benchmark_revocation_check().await?,
            BenchmarkType::TlsAuthentication => {
                println!("TLS Authentication benchmark requires manual setup.");
                println!("Please use the device-client to test TLS authentication.");
                return Ok(());
            }
        };
        
        result.print_report();
        results.push(result);
    } else {
        println!("No benchmark specified. Use --all or --benchmark <type>");
        println!();
        println!("Available benchmarks:");
        println!("  did-creation          - Create a new DID on blockchain (~7s)");
        println!("  did-resolution        - Resolve DID with cold cache (~150ms)");
        println!("  did-resolution-cached - Resolve DID from cache (<1ms)");
        println!("  credential-issuance   - Issue a Verifiable Credential (<5ms)");
        println!("  credential-verification - Verify a credential (<5ms)");
        println!("  revocation-check      - Check revocation status (<1ms)");
        println!("  tls-authentication    - Full TLS + DID auth (manual)");
        println!();
        println!("Example: cargo run --release -p benchmarks -- --all");
        return Ok(());
    }

    // Print summary
    if !results.is_empty() {
        println!("\n");
        println!("╔════════════════════════════════════════════════════════════╗");
        println!("║                      SUMMARY                               ║");
        println!("╚════════════════════════════════════════════════════════════╝");
        println!();
        println!("{:<30} {:>10} {:>10} {:>10}", "Benchmark", "Mean", "P95", "P99");
        println!("{}", "-".repeat(62));
        
        for r in &results {
            println!(
                "{:<30} {:>9.2}ms {:>9.2}ms {:>9.2}ms",
                r.name, r.mean_ms, r.p95_ms, r.p99_ms
            );
        }
        
        println!();

        // Export to CSV if requested
        if let Some(output_file) = args.output {
            export_to_csv(&results, &output_file)?;
        }
    }

    /* Print comparison notes with sources
    println!();
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║              Comparison with Traditional PKI               ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();
    println!("============================================================");
    println!("                    ACADEMIC SOURCES");
    println!("============================================================");
    println!();
    println!("[1] Zhu et al., 'Measuring the Latency and Pervasiveness");
    println!("    of TLS Certificate Revocation'");
    println!("    Passive and Active Measurements Conference (PAM), 2016");
    println!("    https://ant.isi.edu/~johnh/PAPERS/Zhu16a.pdf");
    println!();
    println!("    Key findings:");
    println!("    - Median OCSP latency: 19-20ms (2015-2016 measurements)");
    println!("    - Previous study (Stark et al., 2012): 291ms median");
    println!("    - Long tail: <0.1% of requests took 5s to 8 minutes");
    println!("    - OCSP adds ~10% overhead to TLS handshake time");
    println!("    - 94% of OCSP traffic served by CDNs");
    println!("    - With connection reuse: 10ms median");
    println!("    - Median TLS handshake delay: 242ms");
    println!();
    println!("[2] Liu et al., 'An End-to-End Measurement of Certificate");
    println!("    Revocation in the Web's PKI'");
    println!("    ACM Internet Measurement Conference (IMC), 2015");
    println!("    https://dl.acm.org/doi/10.1145/2815675.2815685");
    println!();
    println!("    Key findings:");
    println!("    - 8% of certificates served on the Internet are revoked");
    println!("    - CRL files can be up to 76MB in size");
    println!("    - OCSP Stapling deployed on only 3% of certificates");
    println!("    - Mobile browsers NEVER check revocation status");
    println!("    - Chrome's CRLSet covers only 0.35% of revocations");
    println!();
    println!("[3] Netcraft, 'Certificate revocation and the performance");
    println!("    of OCSP', April 2013");
    println!("    https://www.netcraft.com/blog/certificate-revocation-and-the-performance-of-ocsp");
    println!();
    println!("    Key findings:");
    println!("    - OCSP responder reliability varies significantly by CA");
    println!("    - Some CAs had >6% request failure rate");
    println!("    - EV certificates require multiple OCSP checks (chain)");
    println!("    - CloudFlare reported 30% improvement with OCSP stapling");
    println!();
    println!("============================================================");
    println!("                 TLS HANDSHAKE TIMES");
    println!("============================================================");
    println!();
    println!("From Zhu et al. (2016) and industry measurements:");
    println!("    - Median TLS handshake time: 242ms [Zhu 2016]");
    println!("    - TLS 1.2 full handshake: 2 round-trips (2-RTT)");
    println!("    - TLS 1.3 full handshake: 1 round-trip (1-RTT)");
    println!("    - TLS 1.3 resumption: 0 round-trips (0-RTT)");
    println!("    - Typical range: 50-300ms depending on network latency");
    println!();
    println!("============================================================");
    println!("                    COMPARISON TABLE");
    println!("============================================================");
    println!();
    println!("{}", "-".repeat(70));
    println!("{:<25} {:>20} {:>22}", "Operation", "This System", "Traditional PKI");
    println!("{}", "-".repeat(70));
    println!("{:<25} {:>20} {:>22}", "Revocation Check", "<1ms (bitmap)", "19-20ms [Zhu 2016]");
    println!("{:<25} {:>20} {:>22}", "", "", "291ms [Stark 2012]");
    println!("{:<25} {:>20} {:>22}", "Worst Case Revocation", "<1ms", "5s-8min (long tail)");
    println!("{:<25} {:>20} {:>22}", "Failure Rate", "0% (on-chain)", "Up to 6% [Netcraft]");
    println!("{:<25} {:>20} {:>22}", "Mobile Support", "Full support", "Never checked [Liu]");
    println!("{:<25} {:>20} {:>22}", "Privacy", "No CA tracking", "CA sees all requests");
    println!("{:<25} {:>20} {:>22}", "Offline Verification", "Yes (cached DID)", "No (needs OCSP)");
    println!("{}", "-".repeat(70));
    println!();
    println!("Note: OCSP performance improved significantly since 2012 due to CDN");
    println!("adoption. However, our bitmap approach provides consistent <1ms lookups");
    println!("with no network dependency once the issuer DID is cached.");
    println!();
    println!("============================================================");
    println!("                    RECENT DEVELOPMENTS");
    println!("============================================================");
    println!();
    println!("2024-2025: Let's Encrypt announced it will stop supporting OCSP");
    println!("in May 2025, citing that browsers don't reliably check revocation");
    println!("status anyway (soft-fail behavior). This validates the need for");
    println!("alternative approaches like our blockchain-based bitmap system.");
    println!();
    println!("Source: Feisty Duck Newsletter, 'The Slow Death of OCSP'");
    println!("https://www.feistyduck.com/newsletter/issue_121_the_slow_death_of_ocsp");
    println!();
    */
    Ok(())
}