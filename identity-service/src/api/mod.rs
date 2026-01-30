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
/// Validates the credential's signature and checks expiration
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

    // Verify
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

// =============================================================================
// HELPERS
// =============================================================================

/// Convert IotaDocument to SimplifiedDIDDocument
fn convert_to_simplified(doc: &identity_iota::iota::IotaDocument) -> SimplifiedDIDDocument {
    // This is a simplified conversion
    // In production, properly extract all fields
    SimplifiedDIDDocument {
        id: doc.id().to_string(),
        verification_methods: vec![], // Would extract from doc
        authentication: None,
        service: None,
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