//! # Cache Module for IOTA Identity IoT System
//!
//! Provides multi-level caching for:
//! - DID Documents (24h TTL)
//! - Verifiable Credentials (12h TTL)
//! - Resolution results
//!
//! Caching is critical for performance since blockchain queries
//! can be slow and the data doesn't change frequently.

use moka::future::Cache;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

use shared::{
    config::CacheConfig,
    types::{DeviceCredential, SimplifiedDIDDocument},
};

/// Cache manager for all cacheable data
pub struct CacheManager {
    /// Cache for DID Documents
    did_cache: Cache<String, Arc<SimplifiedDIDDocument>>,
    
    /// Cache for Verifiable Credentials
    credential_cache: Cache<String, Arc<DeviceCredential>>,
    
    /// Cache for resolution timestamps (to track freshness)
    resolution_cache: Cache<String, std::time::Instant>,
    
    /// Whether caching is enabled
    enabled: bool,
}

impl CacheManager {
    /// Create a new CacheManager with the given configuration
    pub fn new(config: &CacheConfig) -> Self {
        info!(
            enabled = config.enabled,
            did_ttl = config.did_ttl_secs,
            credential_ttl = config.credential_ttl_secs,
            "Initializing cache manager"
        );

        let did_cache = Cache::builder()
            .max_capacity(config.max_did_documents)
            .time_to_live(Duration::from_secs(config.did_ttl_secs))
            .build();

        let credential_cache = Cache::builder()
            .max_capacity(config.max_credentials)
            .time_to_live(Duration::from_secs(config.credential_ttl_secs))
            .build();

        let resolution_cache = Cache::builder()
            .max_capacity(config.max_did_documents)
            .time_to_live(Duration::from_secs(config.did_ttl_secs))
            .build();

        Self {
            did_cache,
            credential_cache,
            resolution_cache,
            enabled: config.enabled,
        }
    }

    /// Create a disabled cache (for testing or when caching is not wanted)
    pub fn disabled() -> Self {
        Self {
            did_cache: Cache::builder().max_capacity(0).build(),
            credential_cache: Cache::builder().max_capacity(0).build(),
            resolution_cache: Cache::builder().max_capacity(0).build(),
            enabled: false,
        }
    }

    // =========================================================================
    // DID DOCUMENT CACHE
    // =========================================================================

    /// Get a DID Document from cache
    pub async fn get_did_document(&self, did: &str) -> Option<Arc<SimplifiedDIDDocument>> {
        if !self.enabled {
            return None;
        }

        let result = self.did_cache.get(did).await;
        if result.is_some() {
            debug!(did = %did, "DID Document cache hit");
        }
        result
    }

    /// Store a DID Document in cache
    pub async fn put_did_document(&self, did: &str, document: SimplifiedDIDDocument) {
        if !self.enabled {
            return;
        }

        debug!(did = %did, "Caching DID Document");
        self.did_cache.insert(did.to_string(), Arc::new(document)).await;
        self.resolution_cache.insert(did.to_string(), std::time::Instant::now()).await;
    }

    /// Invalidate a DID Document in cache
    pub async fn invalidate_did_document(&self, did: &str) {
        debug!(did = %did, "Invalidating DID Document cache");
        self.did_cache.invalidate(did).await;
        self.resolution_cache.invalidate(did).await;
    }

    /// Check if a DID Document is in cache
    pub async fn has_did_document(&self, did: &str) -> bool {
        self.enabled && self.did_cache.contains_key(did)
    }

    // =========================================================================
    // CREDENTIAL CACHE
    // =========================================================================

    /// Get a credential from cache
    pub async fn get_credential(&self, credential_id: &str) -> Option<Arc<DeviceCredential>> {
        if !self.enabled {
            return None;
        }

        let result = self.credential_cache.get(credential_id).await;
        if result.is_some() {
            debug!(credential_id = %credential_id, "Credential cache hit");
        }
        result
    }

    /// Store a credential in cache
    pub async fn put_credential(&self, credential_id: &str, credential: DeviceCredential) {
        if !self.enabled {
            return;
        }

        // Don't cache expired credentials
        if credential.is_expired() {
            debug!(credential_id = %credential_id, "Not caching expired credential");
            return;
        }

        debug!(credential_id = %credential_id, "Caching credential");
        self.credential_cache.insert(credential_id.to_string(), Arc::new(credential)).await;
    }

    /// Invalidate a credential in cache
    pub async fn invalidate_credential(&self, credential_id: &str) {
        debug!(credential_id = %credential_id, "Invalidating credential cache");
        self.credential_cache.invalidate(credential_id).await;
    }

    // =========================================================================
    // CACHE STATISTICS
    // =========================================================================

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            did_cache_size: self.did_cache.entry_count(),
            credential_cache_size: self.credential_cache.entry_count(),
            enabled: self.enabled,
        }
    }

    /// Clear all caches
    pub async fn clear_all(&self) {
        info!("Clearing all caches");
        self.did_cache.invalidate_all();
        self.credential_cache.invalidate_all();
        self.resolution_cache.invalidate_all();
        
        // Run pending maintenance
        self.did_cache.run_pending_tasks().await;
        self.credential_cache.run_pending_tasks().await;
        self.resolution_cache.run_pending_tasks().await;
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Number of DID Documents in cache
    pub did_cache_size: u64,
    /// Number of credentials in cache
    pub credential_cache_size: u64,
    /// Whether caching is enabled
    pub enabled: bool,
}

/// Wrapper that tracks cache hits/misses for metrics
pub struct CachedResolver<R> {
    resolver: R,
    cache: Arc<CacheManager>,
    hits: std::sync::atomic::AtomicU64,
    misses: std::sync::atomic::AtomicU64,
}

impl<R> CachedResolver<R> {
    /// Create a new cached resolver
    pub fn new(resolver: R, cache: Arc<CacheManager>) -> Self {
        Self {
            resolver,
            cache,
            hits: std::sync::atomic::AtomicU64::new(0),
            misses: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Get cache hit rate
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(std::sync::atomic::Ordering::Relaxed);
        let misses = self.misses.load(std::sync::atomic::Ordering::Relaxed);
        let total = hits + misses;
        
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }

    /// Record a cache hit
    pub fn record_hit(&self) {
        self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Record a cache miss
    pub fn record_miss(&self) {
        self.misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::config::CacheConfig;

    #[tokio::test]
    async fn test_did_cache() {
        let config = CacheConfig::default();
        let cache = CacheManager::new(&config);

        let did = "did:iota:0x123";
        let doc = SimplifiedDIDDocument {
            id: did.to_string(),
            verification_methods: vec![],
            authentication: None,
            service: None,
            updated: None,
        };

        // Initially not in cache
        assert!(cache.get_did_document(did).await.is_none());

        // Add to cache
        cache.put_did_document(did, doc.clone()).await;

        // Should be in cache now
        let cached = cache.get_did_document(did).await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().id, did);

        // Invalidate
        cache.invalidate_did_document(did).await;
        assert!(cache.get_did_document(did).await.is_none());
    }

    #[tokio::test]
    async fn test_disabled_cache() {
        let cache = CacheManager::disabled();

        let did = "did:iota:0x123";
        let doc = SimplifiedDIDDocument {
            id: did.to_string(),
            verification_methods: vec![],
            authentication: None,
            service: None,
            updated: None,
        };

        // Should not store when disabled
        cache.put_did_document(did, doc).await;
        assert!(cache.get_did_document(did).await.is_none());
    }
}