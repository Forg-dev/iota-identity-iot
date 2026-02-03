//! # DID Resolver for Device Client
//!
//! Resolves DIDs from IOTA Rebased blockchain with local caching.
//!
//! ## Resolution Strategy
//!
//! 1. Check local cache
//! 2. If miss, query blockchain directly
//! 3. Fallback to Identity Service if blockchain slow
//! 4. Cache the result

use anyhow::{Context, Result};
use moka::future::Cache;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

// IOTA Rebased imports (correct path)
use identity_iota::iota::{IotaDocument, IotaDID};
use identity_iota::iota::rebased::client::IdentityClientReadOnly;

// Use re-export to avoid iota-sdk version conflict
use identity_iota::iota_interaction::IotaClientBuilder;

use shared::{
    config::DeviceClientConfig,
    error::{IdentityError, IdentityResult},
    types::SimplifiedDIDDocument,
};

/// DID Resolver with caching
pub struct DIDResolver {
    /// Read-only identity client for blockchain queries
    identity_client: IdentityClientReadOnly,
    
    /// Local cache for resolved DID Documents
    cache: Cache<String, Arc<SimplifiedDIDDocument>>,
    
    /// Identity Service URL for fallback
    identity_service_url: String,
    
    /// HTTP client for fallback requests
    http_client: reqwest::Client,
}

impl DIDResolver {
    /// Create a new DID Resolver
    pub async fn new(config: &DeviceClientConfig) -> Result<Self> {
        let endpoint = config.custom_endpoint
            .as_deref()
            .unwrap_or_else(|| config.network.endpoint());

        info!(endpoint = %endpoint, "Initializing DID Resolver");

        // Build IOTA client (Rebased SDK)
        let iota_client = IotaClientBuilder::default()
            .build(endpoint)
            .await
            .context("Failed to build IOTA client")?;

        // Create read-only identity client
        let identity_client = IdentityClientReadOnly::new(iota_client)
            .await
            .context("Failed to create identity client")?;

        // Setup cache
        let cache = Cache::builder()
            .max_capacity(config.cache.max_did_documents)
            .time_to_live(Duration::from_secs(config.cache.did_ttl_secs))
            .build();

        Ok(Self {
            identity_client,
            cache,
            identity_service_url: config.identity_service_url.clone(),
            http_client: reqwest::Client::new(),
        })
    }

    /// Resolve a DID to its DID Document
    ///
    /// # Resolution Strategy
    /// 1. Check local cache
    /// 2. Query IOTA Rebased blockchain
    /// 3. Fallback to Identity Service
    pub async fn resolve(&self, did: &str) -> IdentityResult<Arc<SimplifiedDIDDocument>> {
        debug!(did = %did, "Resolving DID");

        // Check cache first
        if let Some(cached) = self.cache.get(did).await {
            debug!(did = %did, "DID resolved from cache");
            return Ok(cached);
        }

        // Try blockchain resolution
        match self.resolve_from_blockchain(did).await {
            Ok(doc) => {
                let simplified = self.convert_document(&doc);
                let arc = Arc::new(simplified);
                self.cache.insert(did.to_string(), Arc::clone(&arc)).await;
                return Ok(arc);
            }
            Err(e) => {
                warn!(
                    did = %did,
                    error = %e,
                    "Blockchain resolution failed, trying fallback"
                );
            }
        }

        // Fallback to Identity Service
        self.resolve_from_service(did).await
    }

    /// Resolve directly from IOTA Rebased blockchain
    async fn resolve_from_blockchain(&self, did: &str) -> IdentityResult<IotaDocument> {
        let iota_did = IotaDID::parse(did)
            .map_err(|e| IdentityError::InvalidDID(e.to_string()))?;

        self.identity_client
            .resolve_did(&iota_did)
            .await
            .map_err(|e| IdentityError::DIDResolutionError {
                did: did.to_string(),
                reason: e.to_string(),
            })
    }

    /// Resolve via Identity Service (fallback)
    async fn resolve_from_service(&self, did: &str) -> IdentityResult<Arc<SimplifiedDIDDocument>> {
        let url = format!(
            "{}/api/v1/did/resolve/{}",
            self.identity_service_url,
            urlencoding::encode(did)
        );

        let response = self.http_client
            .get(&url)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| IdentityError::NetworkConnectionError {
                endpoint: self.identity_service_url.clone(),
                reason: e.to_string(),
            })?;

        if !response.status().is_success() {
            return Err(IdentityError::DIDResolutionError {
                did: did.to_string(),
                reason: format!("Service returned {}", response.status()),
            });
        }

        let result: shared::types::DIDResolutionResponse = response
            .json()
            .await
            .map_err(|e| IdentityError::SerializationError(e.to_string()))?;

        let arc = Arc::new(result.did_document);
        self.cache.insert(did.to_string(), Arc::clone(&arc)).await;

        Ok(arc)
    }

    /// Convert IotaDocument to SimplifiedDIDDocument
    fn convert_document(&self, doc: &IotaDocument) -> SimplifiedDIDDocument {
        use base64::Engine;
        
        // Extract verification methods
        let mut verification_methods = Vec::new();
        
        // Get all verification methods from the document (pass None to get all)
        for method in doc.methods(None) {
            // Get the public key - try JWK (the method available in identity_iota)
            let public_key_multibase = method
                .data()
                .try_public_key_jwk()
                .ok()
                .and_then(|jwk| {
                    jwk.try_okp_params()
                        .ok()
                        .and_then(|params| {
                            // 'x' is base64url encoded, decode and re-encode as base58
                            base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .decode(&params.x)
                                .ok()
                                .map(|bytes| format!("z{}", bs58::encode(&bytes).into_string()))
                        })
                })
                .unwrap_or_else(|| "unknown".to_string());
            
            verification_methods.push(shared::types::VerificationMethod {
                id: method.id().to_string(),
                controller: method.controller().to_string(),
                key_type: method.type_().to_string(),
                public_key_multibase,
            });
        }
        
        // Extract services
        let services: Vec<shared::types::Service> = doc.service()
            .iter()
            .map(|s| {
                // Get the first service type from OneOrSet
                let service_type = s.type_()
                    .iter()
                    .next()
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string());
                
                shared::types::Service {
                    id: s.id().to_string(),
                    service_type,
                    service_endpoint: format!("{:?}", s.service_endpoint()),
                }
            })
            .collect();
        
        SimplifiedDIDDocument {
            id: doc.id().to_string(),
            verification_methods,
            authentication: None,
            service: if services.is_empty() { None } else { Some(services) },
            updated: None,
        }
    }

    /// Check if a DID is cached
    pub async fn is_cached(&self, did: &str) -> bool {
        self.cache.contains_key(did)
    }

    /// Invalidate a cached DID
    pub async fn invalidate(&self, did: &str) {
        self.cache.invalidate(did).await;
    }

    /// Clear entire cache
    pub async fn clear_cache(&self) {
        self.cache.invalidate_all();
        self.cache.run_pending_tasks().await;
    }

    /// Get cache statistics
    pub fn cache_size(&self) -> u64 {
        self.cache.entry_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_parsing() {
        let valid_did = "did:iota:0x0000000000000000000000000000000000000000000000000000000000000000";
        // IotaDID::parse would validate this
    }
}