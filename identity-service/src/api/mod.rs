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
//! - `GET /api/v1/did/resolve/{did}` - Resolve a DID
//! - `POST /api/v1/credential/verify` - Verify a credential

use axum::{
    extract::Path,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Extension, Json, Router,
};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info};

use shared::{error::IdentityError, types::*};

use crate::AppState;

/// Create the API router
pub fn create_router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/device/register", post(register_device))
        .route("/api/v1/did/resolve/{did}", get(resolve_did))
        .route("/api/v1/credential/verify", post(verify_credential))
        .route("/api/v1/credential/revoke", post(revoke_credential))
        .route(
            "/api/v1/credential/status/{credential_id}",
            get(get_credential_status),
        )
        .route(
            "/api/v1/credential/revoke-onchain",
            post(revoke_credential_onchain),
        )
        .route(
            "/api/v1/credential/status-onchain/{index}",
            get(get_credential_status_onchain),
        )
        .route("/api/v1/revocation/bitmap-stats", get(get_bitmap_stats))
        .route("/api/v1/issuer/initialize", post(initialize_issuer_did))
        .route("/api/v1/issuer/status", get(get_issuer_status))
        .route("/api/v1/did/deactivate/{did}", post(deactivate_did))
        .route("/api/v1/did/rotate-key/{did}", post(rotate_key))
        .route("/api/v1/admin/cache/clear", post(clear_caches))
        .route("/metrics", get(get_metrics))
        .layer(Extension(state))
        .layer(cors)
}

// =============================================================================
// HANDLERS
// =============================================================================

async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy",
        "version": shared::VERSION,
    }))
}

async fn register_device(
    Extension(state): Extension<Arc<AppState>>,
    Json(request): Json<DeviceRegistrationRequest>,
) -> Result<Json<DeviceRegistrationResponse>, ApiError> {
    info!(
        public_key_len = request.public_key.len(),
        device_type = ?request.device_type,
        "Device registration request received"
    );

    if request.public_key.len() != 64 {
        return Err(ApiError::BadRequest(
            "Public key must be 64 hex characters (32 bytes)".into(),
        ));
    }

    // Create DID on IOTA Rebased
    let identity = state
        .did_manager
        .create_did(
            &request.public_key,
            request.device_type,
            request.capabilities.clone(),
        )
        .await
        .map_err(ApiError::from)?;

    // Issue credential
    let credential_jwt = state
        .credential_issuer
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
    let expires_at = chrono::Utc::now()
        + chrono::Duration::seconds(state.config.credential.validity_secs as i64);

    Ok(Json(DeviceRegistrationResponse {
        did: identity.did,
        object_id: identity.object_id,
        credential_jwt,
        credential_expires_at: expires_at,
    }))
}

async fn resolve_did(
    Extension(state): Extension<Arc<AppState>>,
    Path(did): Path<String>,
) -> Result<Json<DIDResolutionResponse>, ApiError> {
    let start = std::time::Instant::now();

    let did = urlencoding::decode(&did)
        .map_err(|_| ApiError::BadRequest("Invalid DID encoding".into()))?
        .to_string();

    info!(did = %did, "Resolving DID");

    if let Some(cached) = state.cache.get_did_document(&did).await {
        return Ok(Json(DIDResolutionResponse {
            did_document: (*cached).clone(),
            from_cache: true,
            resolution_time_ms: start.elapsed().as_millis() as u64,
        }));
    }

    let document = state
        .did_manager
        .resolve_did(&did)
        .await
        .map_err(ApiError::from)?;

    let simplified = convert_to_simplified(&document);
    state.cache.put_did_document(&did, simplified.clone()).await;

    Ok(Json(DIDResolutionResponse {
        did_document: simplified,
        from_cache: false,
        resolution_time_ms: start.elapsed().as_millis() as u64,
    }))
}

async fn verify_credential(
    Extension(state): Extension<Arc<AppState>>,
    Json(request): Json<CredentialVerificationRequest>,
) -> Result<Json<CredentialVerificationResponse>, ApiError> {
    info!("Credential verification request received");

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

    let payload_json = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        parts[1],
    )
    .map_err(|_| ApiError::BadRequest("Invalid JWT encoding".into()))?;

    let payload: serde_json::Value = serde_json::from_slice(&payload_json)
        .map_err(|_| ApiError::BadRequest("Invalid JWT payload".into()))?;

    let credential: DeviceCredential =
        serde_json::from_value(payload.get("vc").cloned().unwrap_or_default())
            .map_err(|_| ApiError::BadRequest("Invalid credential in JWT".into()))?;

    if let Some(revocation_entry) = state.revocation_manager.is_revoked(&credential.id) {
        return Ok(Json(CredentialVerificationResponse {
            valid: false,
            subject_did: Some(credential.credential_subject.id),
            issuer_did: Some(credential.issuer),
            error: Some(format!(
                "Credential revoked at {} - Reason: {}",
                revocation_entry.revoked_at,
                revocation_entry
                    .reason
                    .unwrap_or_else(|| "Not specified".to_string())
            )),
            expires_at: Some(credential.expiration_date),
        }));
    }

    match state
        .credential_issuer
        .verify_credential(&credential)
        .await
    {
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

async fn get_metrics(Extension(state): Extension<Arc<AppState>>) -> impl IntoResponse {
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

async fn clear_caches(Extension(state): Extension<Arc<AppState>>) -> impl IntoResponse {
    state.cache.clear_all().await;
    Json(serde_json::json!({
        "status": "ok",
        "message": "All caches cleared"
    }))
}

// =============================================================================
// REVOCATION HANDLERS
// =============================================================================

async fn revoke_credential(
    Extension(state): Extension<Arc<AppState>>,
    Json(request): Json<shared::types::CredentialRevocationRequest>,
) -> Result<Json<shared::types::CredentialRevocationResponse>, ApiError> {
    info!(credential_id = %request.credential_id, "Credential revocation request");

    match state.revocation_manager.revoke(
        &request.credential_id,
        request.reason,
        Some("api".to_string()),
    ) {
        Ok(entry) => {
            state
                .cache
                .invalidate_credential(&request.credential_id)
                .await;

            Ok(Json(shared::types::CredentialRevocationResponse {
                success: true,
                credential_id: entry.credential_id,
                revoked_at: entry.revoked_at,
                error: None,
            }))
        }
        Err(e) => Ok(Json(shared::types::CredentialRevocationResponse {
            success: false,
            credential_id: request.credential_id,
            revoked_at: chrono::Utc::now(),
            error: Some(e.to_string()),
        })),
    }
}

async fn get_credential_status(
    Extension(state): Extension<Arc<AppState>>,
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
// ON-CHAIN REVOCATION (RevocationBitmap2022)
// =============================================================================

async fn revoke_credential_onchain(
    Extension(state): Extension<Arc<AppState>>,
    Json(request): Json<shared::types::OnChainRevocationRequest>,
) -> Result<Json<shared::types::OnChainRevocationResponse>, ApiError> {
    info!(
        credential_id = %request.credential_id,
        revocation_index = request.revocation_index,
        "On-chain credential revocation request (RevocationBitmap2022)"
    );

    match state.onchain_revocation_manager.revoke(
        request.revocation_index,
        &request.credential_id,
        request.reason.clone(),
        Some("api".to_string()),
    ) {
        Ok(()) => {
            state
                .cache
                .invalidate_credential(&request.credential_id)
                .await;

            let issuer_did = state.onchain_revocation_manager.issuer_did();

            if state.did_manager.has_control(&issuer_did) {
                match state.onchain_revocation_manager.encode_service_endpoint() {
                    Ok(bitmap_data_url) => {
                        info!("Publishing updated RevocationBitmap2022 to blockchain...");

                        match state
                            .did_manager
                            .update_revocation_service(&issuer_did, "revocation", &bitmap_data_url)
                            .await
                        {
                            Ok(()) => {
                                state.onchain_revocation_manager.mark_published();
                                state.cache.invalidate_did_document(&issuer_did).await;

                                info!(
                                    credential_id = %request.credential_id,
                                    "Credential revoked and bitmap published on-chain"
                                );

                                Ok(Json(shared::types::OnChainRevocationResponse {
                                    success: true,
                                    credential_id: request.credential_id,
                                    revocation_index: request.revocation_index,
                                    revoked_at: chrono::Utc::now(),
                                    on_chain: true,
                                    transaction_id: None,
                                    error: None,
                                }))
                            }
                            Err(e) => {
                                error!("Failed to publish bitmap on-chain: {}", e);
                                Ok(Json(shared::types::OnChainRevocationResponse {
                                    success: true,
                                    credential_id: request.credential_id,
                                    revocation_index: request.revocation_index,
                                    revoked_at: chrono::Utc::now(),
                                    on_chain: false,
                                    transaction_id: None,
                                    error: Some(format!(
                                        "Revoked locally but failed to publish on-chain: {}",
                                        e
                                    )),
                                }))
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to encode bitmap: {}", e);
                        Ok(Json(shared::types::OnChainRevocationResponse {
                            success: true,
                            credential_id: request.credential_id,
                            revocation_index: request.revocation_index,
                            revoked_at: chrono::Utc::now(),
                            on_chain: false,
                            transaction_id: None,
                            error: Some(format!(
                                "Revoked locally but failed to encode bitmap: {}",
                                e
                            )),
                        }))
                    }
                }
            } else {
                info!(
                    "No on-chain issuer DID found. Revocation is local only. \
                    Call POST /api/v1/issuer/initialize to create issuer DID on-chain."
                );
                Ok(Json(shared::types::OnChainRevocationResponse {
                    success: true,
                    credential_id: request.credential_id,
                    revocation_index: request.revocation_index,
                    revoked_at: chrono::Utc::now(),
                    on_chain: false,
                    transaction_id: None,
                    error: Some("Revoked locally. Issuer DID not initialized on-chain.".into()),
                }))
            }
        }
        Err(e) => Ok(Json(shared::types::OnChainRevocationResponse {
            success: false,
            credential_id: request.credential_id,
            revocation_index: request.revocation_index,
            revoked_at: chrono::Utc::now(),
            on_chain: false,
            transaction_id: None,
            error: Some(e.to_string()),
        })),
    }
}

async fn get_credential_status_onchain(
    Extension(state): Extension<Arc<AppState>>,
    Path(index): Path<u32>,
) -> Result<Json<shared::types::OnChainRevocationStatusResponse>, ApiError> {
    let revoked = state.onchain_revocation_manager.is_revoked(index);

    Ok(Json(shared::types::OnChainRevocationStatusResponse {
        issuer_did: state.onchain_revocation_manager.issuer_did().to_string(),
        revocation_index: index,
        revoked,
        checked_at: chrono::Utc::now(),
        from_chain: false,
    }))
}

async fn get_bitmap_stats(Extension(state): Extension<Arc<AppState>>) -> impl IntoResponse {
    let stats = state.onchain_revocation_manager.stats();

    Json(serde_json::json!({
        "issuer_did": state.onchain_revocation_manager.issuer_did(),
        "total_credentials_issued": stats.total_credentials_issued,
        "revoked_count": stats.revoked_count,
        "is_dirty": stats.is_dirty,
        "serialized_size_bytes": stats.serialized_size_bytes,
        "revocation_type": "RevocationBitmap2022"
    }))
}

// =============================================================================
// ISSUER DID MANAGEMENT
// =============================================================================

async fn initialize_issuer_did(
    Extension(state): Extension<Arc<AppState>>,
) -> Result<impl IntoResponse, ApiError> {
    info!("Initializing issuer DID on-chain with RevocationBitmap2022 service");

    if let Some(existing_did) = state.did_manager.get_issuer_did_string() {
        if state.did_manager.has_control(&existing_did) {
            return Ok(Json(serde_json::json!({
                "success": true,
                "issuer_did": existing_did,
                "revocation_service_id": format!("{}#revocation", existing_did),
                "on_chain": true,
                "message": "Issuer DID already initialized"
            })));
        }
    }

    let public_key_hex = state.credential_issuer.public_key_hex();
    info!(public_key = %public_key_hex, "Using CredentialIssuer's public key for issuer DID");

    match state
        .did_manager
        .create_issuer_did_with_key(&public_key_hex)
        .await
    {
        Ok(creation_result) => {
            let did_str = creation_result.did.clone();
            info!(issuer_did = %did_str, "Issuer DID created on-chain");

            state.credential_issuer.set_issuer_did(did_str.clone());
            state
                .onchain_revocation_manager
                .set_issuer_did(did_str.clone());

            let bitmap_data_url = state
                .onchain_revocation_manager
                .encode_service_endpoint()
                .map_err(|e| ApiError::Internal(format!("Failed to encode bitmap: {}", e)))?;

            match state
                .did_manager
                .update_revocation_service(&did_str, "revocation", &bitmap_data_url)
                .await
            {
                Ok(()) => {
                    info!(
                        issuer_did = %did_str,
                        "RevocationBitmap2022 service added to issuer DID"
                    );

                    if let Err(e) = state.credential_issuer.save_issuer_identity_with_tx_key(
                        &did_str,
                        &creation_result.tx_private_key_hex,
                        &creation_result.fragment,
                    ) {
                        error!("Failed to save issuer identity: {}", e);
                    }

                    Ok(Json(serde_json::json!({
                        "success": true,
                        "issuer_did": did_str,
                        "revocation_service_id": format!("{}#revocation", did_str),
                        "on_chain": true,
                        "message": "Issuer DID created with RevocationBitmap2022 service"
                    })))
                }
                Err(e) => {
                    error!("Failed to add revocation service: {}", e);
                    if let Err(save_err) = state.credential_issuer.save_issuer_identity_with_tx_key(
                        &did_str,
                        &creation_result.tx_private_key_hex,
                        &creation_result.fragment,
                    ) {
                        error!("Failed to save issuer identity: {}", save_err);
                    }

                    Ok(Json(serde_json::json!({
                        "success": true,
                        "issuer_did": did_str,
                        "revocation_service_id": null,
                        "on_chain": true,
                        "message": format!("Issuer DID created but revocation service failed: {}", e)
                    })))
                }
            }
        }
        Err(e) => {
            error!("Failed to create issuer DID: {}", e);
            Err(ApiError::Internal(format!(
                "Failed to create issuer DID: {}",
                e
            )))
        }
    }
}

async fn get_issuer_status(Extension(state): Extension<Arc<AppState>>) -> impl IntoResponse {
    let issuer_did = state.onchain_revocation_manager.issuer_did().to_string();
    let has_control = state.did_manager.has_control(&issuer_did);
    let onchain_issuer = state.did_manager.get_issuer_did_string();
    let stats = state.onchain_revocation_manager.stats();

    Json(serde_json::json!({
        "issuer_did": issuer_did,
        "on_chain_did": onchain_issuer,
        "has_control": has_control,
        "initialized_on_chain": onchain_issuer.is_some() && has_control,
        "revocation_bitmap": {
            "total_credentials_issued": stats.total_credentials_issued,
            "revoked_count": stats.revoked_count,
            "needs_publish": stats.is_dirty,
        },
        "instructions": if !has_control {
            "Call POST /api/v1/issuer/initialize to create issuer DID on-chain"
        } else {
            "Issuer DID is ready. Revocations will be published on-chain."
        }
    }))
}

// =============================================================================
// DID DEACTIVATION
// =============================================================================

async fn deactivate_did(
    Extension(state): Extension<Arc<AppState>>,
    Path(did): Path<String>,
) -> Result<Json<shared::types::DIDDeactivationResponse>, ApiError> {
    let did = urlencoding::decode(&did)
        .map_err(|_| ApiError::BadRequest("Invalid DID encoding".into()))?
        .to_string();

    info!(did = %did, "DID deactivation request (on-chain)");

    if !state.did_manager.has_control(&did) {
        return Ok(Json(shared::types::DIDDeactivationResponse {
            success: false,
            did,
            deactivated_at: chrono::Utc::now(),
            on_chain: false,
            transaction_id: None,
            error: Some("Cannot deactivate: DID was not created by this service".into()),
        }));
    }

    match state.did_manager.deactivate_did(&did).await {
        Ok(()) => {
            state.cache.invalidate_did_document(&did).await;

            // Revoke in-memory (for local checks)
            let _ = state.revocation_manager.revoke(
                &did,
                Some("DID deactivated on-chain".to_string()),
                Some("system".to_string()),
            );

            // Also revoke on-chain via RevocationBitmap2022 if credential index is known.
            // This ensures the revocation persists across server restarts and is
            // verifiable by any party resolving the issuer's DID Document.
            if let Some(index) = state.onchain_revocation_manager.get_index_for_credential(&did) {
                if let Ok(()) = state.onchain_revocation_manager.revoke(
                    index,
                    &did,
                    Some("DID deactivated on-chain".to_string()),
                    Some("system".to_string()),
                ) {
                    // Publish updated bitmap on-chain
                    let issuer_did = state.onchain_revocation_manager.issuer_did();
                    if state.did_manager.has_control(&issuer_did) {
                        if let Ok(bitmap_data_url) = state.onchain_revocation_manager.encode_service_endpoint() {
                            let _ = state.did_manager
                                .update_revocation_service(&issuer_did, "revocation", &bitmap_data_url)
                                .await;
                            state.onchain_revocation_manager.mark_published();
                            state.cache.invalidate_did_document(&issuer_did).await;
                        }
                    }
                }
            }

            Ok(Json(shared::types::DIDDeactivationResponse {
                success: true,
                did,
                deactivated_at: chrono::Utc::now(),
                on_chain: true,
                transaction_id: None,
                error: None,
            }))
        }
        Err(e) => Ok(Json(shared::types::DIDDeactivationResponse {
            success: false,
            did,
            deactivated_at: chrono::Utc::now(),
            on_chain: false,
            transaction_id: None,
            error: Some(e.to_string()),
        })),
    }
}

// =============================================================================
// KEY ROTATION
// =============================================================================

async fn rotate_key(
    Extension(state): Extension<Arc<AppState>>,
    Path(did): Path<String>,
    Json(request): Json<shared::types::KeyRotationRequest>,
) -> Result<Json<shared::types::KeyRotationResponse>, ApiError> {
    let did = urlencoding::decode(&did)
        .map_err(|_| ApiError::BadRequest("Invalid DID encoding".into()))?
        .to_string();

    info!(did = %did, "Key rotation request (on-chain)");

    if request.new_public_key.len() != 64 {
        return Err(ApiError::BadRequest(
            "New public key must be 64 hex characters (32 bytes)".into(),
        ));
    }

    if !state.did_manager.has_control(&did) {
        return Ok(Json(shared::types::KeyRotationResponse {
            success: false,
            did,
            new_verification_method_id: None,
            rotated_at: chrono::Utc::now(),
            error: Some("Cannot rotate key: DID was not created by this service".into()),
        }));
    }

    match state
        .did_manager
        .rotate_key(&did, &request.new_public_key)
        .await
    {
        Ok(new_fragment) => {
            state.cache.invalidate_did_document(&did).await;

            Ok(Json(shared::types::KeyRotationResponse {
                success: true,
                did,
                new_verification_method_id: Some(new_fragment),
                rotated_at: chrono::Utc::now(),
                error: None,
            }))
        }
        Err(e) => Ok(Json(shared::types::KeyRotationResponse {
            success: false,
            did,
            new_verification_method_id: None,
            rotated_at: chrono::Utc::now(),
            error: Some(e.to_string()),
        })),
    }
}

// =============================================================================
// HELPERS
// =============================================================================

fn convert_to_simplified(doc: &identity_iota::iota::IotaDocument) -> SimplifiedDIDDocument {
    use base64::Engine;
    use shared::types::VerificationMethod;

    let verification_methods: Vec<VerificationMethod> = doc
        .methods(None)
        .into_iter()
        .map(|method| {
            let public_key_multibase = method
                .data()
                .try_public_key_jwk()
                .ok()
                .and_then(|jwk| {
                    jwk.try_okp_params().ok().and_then(|params| {
                        base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(&params.x)
                            .ok()
                            .map(|bytes| format!("z{}", bs58::encode(&bytes).into_string()))
                    })
                })
                .unwrap_or_else(|| "unknown".to_string());

            VerificationMethod {
                id: method.id().to_string(),
                controller: method.controller().to_string(),
                key_type: method.type_().to_string(),
                public_key_multibase,
            }
        })
        .collect();

    let authentication: Option<Vec<String>> = {
        let auth_methods: Vec<String> = doc
            .methods(Some(
                identity_iota::verification::MethodScope::authentication(),
            ))
            .into_iter()
            .map(|m| m.id().to_string())
            .collect();
        if auth_methods.is_empty() {
            None
        } else {
            Some(auth_methods)
        }
    };

    let service: Option<Vec<shared::types::Service>> = {
        let services: Vec<shared::types::Service> = doc
            .service()
            .iter()
            .map(|s| {
                let service_type = s
                    .type_()
                    .iter()
                    .next()
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string());

                let service_endpoint = match s.service_endpoint() {
                    identity_iota::document::ServiceEndpoint::One(url) => url.to_string(),
                    other => format!("{}", other),
                };

                shared::types::Service {
                    id: s.id().to_string(),
                    service_type,
                    service_endpoint,
                }
            })
            .collect();
        if services.is_empty() {
            None
        } else {
            Some(services)
        }
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

            IdentityError::DIDDeactivated(_) | IdentityError::DIDAlreadyDeactivated(_) => {
                ApiError::BadRequest(err.to_string())
            }

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