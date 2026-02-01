//! # REST API for Identity Service
//!
//! Provides HTTP endpoints for:
//! - Device registration (create DID + issue credential)
//! - DID resolution
//! - Credential verification
//!
//! ## Endpoints
//!
//! - `POST /api/v1/device/register` - Register a new device
//! - `GET /api/v1/did/resolve/:did` - Resolve a DID
//! - `POST /api/v1/credential/verify` - Verify a credential

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info};

use shared::{
    error::IdentityError,
    types::*,
};

use crate::AppState;

/// Create the API router
pub fn create_router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        // Health check
        .route("/health", get(health_check))
        // API v1 routes
        .route("/api/v1/device/register", post(register_device))
        .route("/api/v1/did/resolve/:did", get(resolve_did))
        .route("/api/v1/credential/verify", post(verify_credential))
        // Revocation endpoints
        .route("/api/v1/credential/revoke", post(revoke_credential))
        .route("/api/v1/credential/status/:credential_id", get(get_credential_status))
        // On-chain DID operations
        .route("/api/v1/did/deactivate/:did", post(deactivate_did))  // NUOVA
        .route("/api/v1/did/rotate-key/:did", post(rotate_key))
        // Cache management (admin)
        .route("/api/v1/admin/cache/clear", post(clear_caches))
        // Metrics
        .route("/metrics", get(get_metrics))
        .layer(cors)
        .with_state(state)
}

// =============================================================================
// HANDLERS
// =============================================================================

/// Health check endpoint
async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy",
        "version": shared::VERSION,
    }))
}

/// Register a new device
///
/// Creates a DID on IOTA Rebased and issues a Verifiable Credential
///
/// # Request Body
/// ```json
/// {
///   "public_key": "hex-encoded-ed25519-public-key",
///   "device_type": "sensor",
///   "capabilities": ["temperature", "humidity"]
/// }
/// ```
///
/// # Response
/// ```json
/// {
///   "did": "did:iota:0x...",
///   "object_id": "0x...",
///   "credential_jwt": "eyJ...",
///   "credential_expires_at": "2025-01-01T00:00:00Z"
/// }
/// ```
async fn register_device(
    State(state): State<Arc<AppState>>,
    Json(request): Json<DeviceRegistrationRequest>,
) -> Result<Json<DeviceRegistrationResponse>, ApiError> {
    info!(
        public_key_len = request.public_key.len(),
        device_type = ?request.device_type,
        "Device registration request received"
    );

    // Validate public key format
    if request.public_key.len() != 64 {
        return Err(ApiError::BadRequest(
            "Public key must be 64 hex characters (32 bytes)".into()
        ));
    }

    // Create DID on IOTA Rebased
    let identity = state.did_manager
        .create_did(
            &request.public_key,
            request.device_type,
            request.capabilities.clone(),
        )
        .await
        .map_err(ApiError::from)?;

    // Issue credential
    let credential_jwt = state.credential_issuer
        .issue_credential_jwt(
            &identity.did,
            request.device_type,
            request.capabilities,
            Some(crate::credential::CredentialMetadata {
                manufacturer: request.manufacturer,
                model: request.model,
                ..Default::default()
            }),
        )
        .await
        .map_err(ApiError::from)?;

    // Calculate expiration
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(
        state.config.credential.validity_secs as i64
    );

    Ok(Json(DeviceRegistrationResponse {
        did: identity.did,
        object_id: identity.object_id,
        credential_jwt,
        credential_expires_at: expires_at,
    }))
}

/// Resolve a DID
///
/// Fetches the DID Document from IOTA Rebased blockchain
async fn resolve_did(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
) -> Result<Json<DIDResolutionResponse>, ApiError> {
    let start = std::time::Instant::now();
    
    // URL decode the DID
    let did = urlencoding::decode(&did)
        .map_err(|_| ApiError::BadRequest("Invalid DID encoding".into()))?
        .to_string();

    info!(did = %did, "Resolving DID");

    // Check cache first
    let from_cache = if let Some(cached) = state.cache.get_did_document(&did).await {
        return Ok(Json(DIDResolutionResponse {
            did_document: (*cached).clone(),
            from_cache: true,
            resolution_time_ms: start.elapsed().as_millis() as u64,
        }));
    } else {
        false
    };

    // Resolve from blockchain
    let document = state.did_manager
        .resolve_did(&did)
        .await
        .map_err(ApiError::from)?;

    // Convert to simplified format
    let simplified = convert_to_simplified(&document);

    // Cache the result
    state.cache.put_did_document(&did, simplified.clone()).await;

    Ok(Json(DIDResolutionResponse {
        did_document: simplified,
        from_cache,
        resolution_time_ms: start.elapsed().as_millis() as u64,
    }))
}

/// Verify a credential
///
/// Validates the credential's signature, checks expiration, and verifies
/// it has not been revoked.
async fn verify_credential(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CredentialVerificationRequest>,
) -> Result<Json<CredentialVerificationResponse>, ApiError> {
    info!("Credential verification request received");

    // Parse JWT (simplified - in production use a proper JWT library)
    let parts: Vec<&str> = request.credential_jwt.split('.').collect();
    if parts.len() != 3 {
        return Ok(Json(CredentialVerificationResponse {
            valid: false,
            subject_did: None,
            issuer_did: None,
            error: Some("Invalid JWT format".into()),
            expires_at: None,
        }));
    }

    // Decode payload
    let payload_json = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        parts[1]
    ).map_err(|_| ApiError::BadRequest("Invalid JWT encoding".into()))?;

    let payload: serde_json::Value = serde_json::from_slice(&payload_json)
        .map_err(|_| ApiError::BadRequest("Invalid JWT payload".into()))?;

    // Extract credential
    let credential: DeviceCredential = serde_json::from_value(
        payload.get("vc").cloned().unwrap_or_default()
    ).map_err(|_| ApiError::BadRequest("Invalid credential in JWT".into()))?;

    // Check if credential is revoked
    if let Some(revocation_entry) = state.revocation_manager.is_revoked(&credential.id) {
        return Ok(Json(CredentialVerificationResponse {
            valid: false,
            subject_did: Some(credential.credential_subject.id),
            issuer_did: Some(credential.issuer),
            error: Some(format!(
                "Credential revoked at {} - Reason: {}",
                revocation_entry.revoked_at,
                revocation_entry.reason.unwrap_or_else(|| "Not specified".to_string())
            )),
            expires_at: Some(credential.expiration_date),
        }));
    }

    // Verify signature and expiration
    match state.credential_issuer.verify_credential(&credential).await {
        Ok(()) => Ok(Json(CredentialVerificationResponse {
            valid: true,
            subject_did: Some(credential.credential_subject.id),
            issuer_did: Some(credential.issuer),
            error: None,
            expires_at: Some(credential.expiration_date),
        })),
        Err(e) => Ok(Json(CredentialVerificationResponse {
            valid: false,
            subject_did: None,
            issuer_did: None,
            error: Some(e.to_string()),
            expires_at: None,
        })),
    }
}

/// Get service metrics
async fn get_metrics(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let cache_stats = state.cache.stats();
    
    Json(serde_json::json!({
        "cache": {
            "did_documents": cache_stats.did_cache_size,
            "credentials": cache_stats.credential_cache_size,
            "enabled": cache_stats.enabled,
        },
        "network": state.config.network.to_string(),
        "endpoint": state.did_manager.endpoint(),
    }))
}

/// Clear all caches (admin endpoint)
async fn clear_caches(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    state.cache.clear_all().await;
    Json(serde_json::json!({
        "status": "ok",
        "message": "All caches cleared"
    }))
}

// =============================================================================
// REVOCATION HANDLERS
// =============================================================================

/// Revoke a credential
///
/// Marks a credential as revoked. Once revoked, the credential will fail verification.
///
/// # Request Body
/// ```json
/// {
///   "credential_id": "unique-credential-id",
///   "reason": "optional reason for revocation"
/// }
/// ```
async fn revoke_credential(
    State(state): State<Arc<AppState>>,
    Json(request): Json<shared::types::CredentialRevocationRequest>,
) -> Result<Json<shared::types::CredentialRevocationResponse>, ApiError> {
    info!(credential_id = %request.credential_id, "Credential revocation request");
    
    match state.revocation_manager.revoke(
        &request.credential_id,
        request.reason,
        Some("api".to_string()),
    ) {
        Ok(entry) => {
            // Invalidate from cache if present
            state.cache.invalidate_credential(&request.credential_id).await;
            
            Ok(Json(shared::types::CredentialRevocationResponse {
                success: true,
                credential_id: entry.credential_id,
                revoked_at: entry.revoked_at,
                error: None,
            }))
        }
        Err(e) => {
            Ok(Json(shared::types::CredentialRevocationResponse {
                success: false,
                credential_id: request.credential_id,
                revoked_at: chrono::Utc::now(),
                error: Some(e.to_string()),
            }))
        }
    }
}

/// Get credential revocation status
///
/// Check if a credential has been revoked
async fn get_credential_status(
    State(state): State<Arc<AppState>>,
    Path(credential_id): Path<String>,
) -> Result<Json<shared::types::CredentialStatusResponse>, ApiError> {
    let credential_id = urlencoding::decode(&credential_id)
        .map_err(|_| ApiError::BadRequest("Invalid credential ID encoding".into()))?
        .to_string();
    
    let (revoked, entry) = state.revocation_manager.get_status(&credential_id);
    
    Ok(Json(shared::types::CredentialStatusResponse {
        credential_id,
        revoked,
        revoked_at: entry.as_ref().map(|e| e.revoked_at),
        reason: entry.and_then(|e| e.reason),
    }))
}

// =============================================================================
// DID DEACTIVATION (ON-CHAIN REVOCATION)
// =============================================================================

/// Deactivate a DID on the blockchain
async fn deactivate_did(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
) -> Result<Json<shared::types::DIDDeactivationResponse>, ApiError> {
    let did = urlencoding::decode(&did)
        .map_err(|_| ApiError::BadRequest("Invalid DID encoding".into()))?
        .to_string();
    
    info!(did = %did, "DID deactivation request (on-chain)");
    
    // Check if we have control over this DID
    if !state.did_manager.has_control(&did) {
        return Ok(Json(shared::types::DIDDeactivationResponse {
            success: false,
            did,
            deactivated_at: chrono::Utc::now(),
            transaction_id: None,
            error: Some("Cannot deactivate: DID was not created by this service".into()),
        }));
    }
    
    // Perform on-chain deactivation
    match state.did_manager.deactivate_did(&did).await {
        Ok(()) => {
            // Invalidate cache
            state.cache.invalidate_did_document(&did).await;
            
            // Also mark in revocation manager for consistency
            let _ = state.revocation_manager.revoke(
                &did,
                Some("DID deactivated on-chain".to_string()),
                Some("system".to_string()),
            );
            
            Ok(Json(shared::types::DIDDeactivationResponse {
                success: true,
                did,
                deactivated_at: chrono::Utc::now(),
                transaction_id: None,
                error: None,
            }))
        }
        Err(e) => {
            Ok(Json(shared::types::DIDDeactivationResponse {
                success: false,
                did,
                deactivated_at: chrono::Utc::now(),
                transaction_id: None,
                error: Some(e.to_string()),
            }))
        }
    }
}

// =============================================================================
// KEY ROTATION HANDLERS
// =============================================================================

/// Rotate a device's verification key
///
/// Updates the DID Document with a new verification method.
/// The old key is optionally revoked.
///
/// # Note
/// This is a complex operation that requires:
/// 1. Resolving the existing DID Document
/// 2. Adding a new verification method
/// 3. Publishing the updated document to blockchain
///
/// Current implementation is a placeholder - full implementation requires
/// signing capability for the existing DID.
/// Rotate a device's verification key on the blockchain
async fn rotate_key(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
    Json(request): Json<shared::types::KeyRotationRequest>,
) -> Result<Json<shared::types::KeyRotationResponse>, ApiError> {
    let did = urlencoding::decode(&did)
        .map_err(|_| ApiError::BadRequest("Invalid DID encoding".into()))?
        .to_string();
    
    info!(did = %did, "Key rotation request (on-chain)");
    
    // Validate new public key format
    if request.new_public_key.len() != 64 {
        return Err(ApiError::BadRequest(
            "New public key must be 64 hex characters (32 bytes)".into()
        ));
    }
    
    // Check if we have control over this DID
    if !state.did_manager.has_control(&did) {
        return Ok(Json(shared::types::KeyRotationResponse {
            success: false,
            did,
            new_verification_method_id: None,
            rotated_at: chrono::Utc::now(),
            error: Some("Cannot rotate key: DID was not created by this service".into()),
        }));
    }
    
    // Perform on-chain key rotation
    match state.did_manager.rotate_key(&did, &request.new_public_key).await {
        Ok(new_fragment) => {
            // Invalidate cache for this DID
            state.cache.invalidate_did_document(&did).await;
            
            Ok(Json(shared::types::KeyRotationResponse {
                success: true,
                did,
                new_verification_method_id: Some(new_fragment),
                rotated_at: chrono::Utc::now(),
                error: None,
            }))
        }
        Err(e) => {
            Ok(Json(shared::types::KeyRotationResponse {
                success: false,
                did,
                new_verification_method_id: None,
                rotated_at: chrono::Utc::now(),
                error: Some(e.to_string()),
            }))
        }
    }
}

// =============================================================================
// HELPERS
// =============================================================================

/// Convert IotaDocument to SimplifiedDIDDocument
fn convert_to_simplified(doc: &identity_iota::iota::IotaDocument) -> SimplifiedDIDDocument {
    use shared::types::VerificationMethod;
    
    // Extract verification methods from the document
    let verification_methods: Vec<VerificationMethod> = doc
        .methods(None)
        .into_iter()  // Aggiunto into_iter()
        .map(|method| {
            // Get the public key in multibase format
            let public_key_multibase = method
                .data()
                .try_public_key_jwk()
                .map(|jwk| {
                    // Convert JWK to multibase (simplified - use x value for Ed25519)
                    jwk.try_okp_params()
                        .map(|params| format!("z{}", base64::Engine::encode(
                            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                            &params.x
                        )))
                        .unwrap_or_else(|_| "unknown".to_string())
                })
                .unwrap_or_else(|_| "unknown".to_string());
            
            VerificationMethod {
                id: method.id().to_string(),
                controller: method.controller().to_string(),
                key_type: method.type_().to_string(),
                public_key_multibase,
            }
        })
        .collect();
    
    // Extract authentication method IDs
    let authentication: Option<Vec<String>> = {
        let auth_methods: Vec<String> = doc
            .methods(Some(identity_iota::verification::MethodScope::authentication()))
            .into_iter()  // Aggiunto into_iter()
            .map(|m| m.id().to_string())
            .collect();
        if auth_methods.is_empty() { None } else { Some(auth_methods) }
    };
    
    // Extract services if any
    let service: Option<Vec<shared::types::Service>> = {
        let services: Vec<shared::types::Service> = doc
            .service()
            .iter()
            .map(|s| shared::types::Service {
                id: s.id().to_string(),
                service_type: s.type_().first().cloned().unwrap_or_default(),  // Usa first() invece di to_string()
                service_endpoint: s.service_endpoint().to_string(),
            })
            .collect();
        if services.is_empty() { None } else { Some(services) }
    };
    
    SimplifiedDIDDocument {
        id: doc.id().to_string(),
        verification_methods,
        authentication,
        service,
        updated: None,
    }
}

// =============================================================================
// ERROR HANDLING
// =============================================================================

/// API error type
#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    NotFound(String),
    Internal(String),
}

impl From<IdentityError> for ApiError {
    fn from(err: IdentityError) -> Self {
        match err {
            IdentityError::InvalidDID(_)
            | IdentityError::InvalidPublicKey(_)
            | IdentityError::InvalidCredential(_)
            | IdentityError::InvalidRequest(_) => ApiError::BadRequest(err.to_string()),
            
            IdentityError::DIDNotFound(_) => ApiError::NotFound(err.to_string()),
            
            IdentityError::DIDDeactivated(_)
            | IdentityError::DIDAlreadyDeactivated(_) => ApiError::BadRequest(err.to_string()),
            
            IdentityError::UnauthorizedOperation(_) => ApiError::BadRequest(err.to_string()),
            
            IdentityError::DIDUpdateError(_) => ApiError::Internal(err.to_string()),
            
            _ => ApiError::Internal(err.to_string()),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            ApiError::Internal(msg) => {
                error!(error = %msg, "Internal server error");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".into())
            }
        };

        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_error_conversion() {
        let err = IdentityError::InvalidDID("bad did".into());
        let api_err: ApiError = err.into();
        matches!(api_err, ApiError::BadRequest(_));
    }
}