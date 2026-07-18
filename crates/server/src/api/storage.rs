//! Storage API Handlers
//! HTTP endpoints for file upload/download operations

use axum::{
    body::Body,
    extract::{Multipart, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::api::common::{map_error, ApiResponse};
use crate::api::middleware::authz;
use crate::core::auth::Permission;
use crate::core::storage::StorageManager;
use crate::AppState;

#[derive(Debug, Serialize)]
pub struct UploadResponse {
    pub hash: String,
    pub size_bytes: u64,
    pub original_path: String,
}

async fn require_permission(
    state: &AppState,
    headers: &HeaderMap,
    permission: Permission,
) -> Result<(), (StatusCode, String)> {
    authz::require_permission(state, headers, permission)
        .await
        .map(|_| ())?;
    Ok(())
}

/// POST /v2/storage/upload
/// Upload a file via multipart form
pub async fn upload_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> (StatusCode, Json<ApiResponse<UploadResponse>>) {
    if let Err((status, message)) = require_permission(&state, &headers, Permission::Upload).await {
        return (status, Json(ApiResponse::err(message)));
    }
    let event_meta = crate::core::events::EventMetadata::from_headers(&headers);

    // Get the first file field
    let field = match multipart.next_field().await {
        Ok(Some(f)) => f,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::err("No file provided")),
            )
        }
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::err(format!("Multipart error: {}", e))),
            )
        }
    };

    let filename = field.file_name().unwrap_or("unknown").to_string();

    let data = match field.bytes().await {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::err(format!("Failed to read file: {}", e))),
            )
        }
    };

    match state.storage_manager.store(&data, &filename).await {
        Ok(stored) => {
            if let Some(event_store) = &state.event_store {
                if let Err(error) = event_store
                    .append(
                        "BLOB_UPLOADED",
                        "storage-upload",
                        None,
                        None,
                        json!({
                            "hash": stored.hash,
                            "size_bytes": stored.size_bytes,
                            "original_path": stored.original_path,
                        }),
                        &event_meta,
                    )
                    .await
                {
                    tracing::warn!("failed to append blob upload event: {error}");
                }
            }
            (
                StatusCode::OK,
                Json(ApiResponse::ok(UploadResponse {
                    hash: stored.hash,
                    size_bytes: stored.size_bytes,
                    original_path: stored.original_path,
                })),
            )
        }
        Err(error) => {
            let (status, response) = map_error::<UploadResponse>(error);
            (status, Json(response))
        }
    }
}

/// GET /v2/storage/download/:hash
/// Download a file by its hash
pub async fn download_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(hash): Path<String>,
) -> Response {
    if let Err((status, message)) = require_permission(&state, &headers, Permission::Download).await
    {
        return (status, message).into_response();
    }

    match state.storage_manager.retrieve(&hash).await {
        Ok(data) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", hash),
            )
            .body(Body::from(data))
            .unwrap(),
        Err(error) => {
            let (status, response) = map_error::<()>(error);
            (status, Json(response)).into_response()
        }
    }
}

/// GET /v2/storage/exists/:hash
/// Check if a file exists
pub async fn check_exists(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(hash): Path<String>,
) -> (StatusCode, Json<ApiResponse<bool>>) {
    if let Err((status, message)) = require_permission(&state, &headers, Permission::Download).await
    {
        return (status, Json(ApiResponse::err(message)));
    }
    if let Err(error) = StorageManager::validate_hash(&hash) {
        let (status, response) = map_error::<bool>(error);
        return (status, Json(response));
    }

    match state.storage_manager.exists(&hash).await {
        Ok(exists) => (StatusCode::OK, Json(ApiResponse::ok(exists))),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::err(error)),
        ),
    }
}

/// GET /v2/storage/hash
/// Calculate hash of provided data (for client-side deduplication check)
#[derive(Debug, Deserialize)]
pub struct HashRequest {
    pub data: String, // Base64 encoded
}

#[derive(Debug, Serialize)]
pub struct HashResponse {
    pub hash: String,
}

pub async fn calculate_hash(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<HashRequest>,
) -> (StatusCode, Json<ApiResponse<HashResponse>>) {
    if let Err((status, message)) = require_permission(&state, &headers, Permission::Upload).await {
        return (status, Json(ApiResponse::err(message)));
    }

    use base64::Engine;

    match base64::engine::general_purpose::STANDARD.decode(&payload.data) {
        Ok(data) => {
            let hash = StorageManager::calculate_hash(&data);
            (StatusCode::OK, Json(ApiResponse::ok(HashResponse { hash })))
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err(format!("Invalid base64: {}", e))),
        ),
    }
}
