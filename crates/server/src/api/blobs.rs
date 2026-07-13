use std::collections::HashSet;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::api::{common::ApiResponse, middleware::authz};
use crate::core::{auth::Permission, storage::StorageManager};
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct MissingChunksRequest {
    pub chunk_hashes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct MissingChunksResponse {
    pub missing: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct UploadChunkResponse {
    pub chunk_hash: String,
    pub size_bytes: u64,
    pub uploaded: bool,
}

async fn require_upload_permission(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, String)> {
    authz::require_permission(state, headers, Permission::Upload)
        .await
        .map(|_| ())
}

async fn require_download_permission(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, String)> {
    authz::require_permission(state, headers, Permission::Download)
        .await
        .map(|_| ())
}

pub async fn missing_chunks(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<MissingChunksRequest>,
) -> (StatusCode, Json<ApiResponse<MissingChunksResponse>>) {
    if let Err((status, message)) = require_download_permission(&state, &headers).await {
        return (status, Json(ApiResponse::err(message)));
    }

    if payload.chunk_hashes.is_empty() {
        return (
            StatusCode::OK,
            Json(ApiResponse::ok(MissingChunksResponse { missing: vec![] })),
        );
    }

    let mut unique_hashes = payload.chunk_hashes.clone();
    unique_hashes.sort();
    unique_hashes.dedup();
    if unique_hashes
        .iter()
        .any(|hash| StorageManager::validate_hash(hash).is_err())
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err("invalid chunk hash")),
        );
    }

    let missing = if let Some(pool) = state.db_pool.as_ref() {
        match sqlx::query_scalar::<_, String>(
            r#"
            SELECT chunk_hash
            FROM chunks
            WHERE chunk_hash = ANY($1)
            "#,
        )
        .bind(&unique_hashes)
        .fetch_all(pool)
        .await
        {
            Ok(existing) => {
                let existing_set: HashSet<String> = existing.into_iter().collect();
                unique_hashes
                    .into_iter()
                    .filter(|hash| !existing_set.contains(hash))
                    .collect::<Vec<_>>()
            }
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiResponse::err(format!(
                        "failed to query chunk metadata: {error}"
                    ))),
                );
            }
        }
    } else {
        let mut missing = Vec::new();
        for hash in unique_hashes {
            match state.storage_manager.exists(&hash).await {
                Ok(true) => {}
                Ok(false) => missing.push(hash),
                Err(error) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ApiResponse::err(format!(
                            "failed to check chunk existence: {error}"
                        ))),
                    );
                }
            }
        }
        missing
    };

    (
        StatusCode::OK,
        Json(ApiResponse::ok(MissingChunksResponse { missing })),
    )
}

pub async fn upload_chunk(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chunk_hash): Path<String>,
    body: Bytes,
) -> (StatusCode, Json<ApiResponse<UploadChunkResponse>>) {
    if let Err((status, message)) = require_upload_permission(&state, &headers).await {
        return (status, Json(ApiResponse::err(message)));
    }

    if chunk_hash.len() < 3 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err("chunk_hash too short")),
        );
    }

    let calculated = StorageManager::calculate_hash(&body);
    if calculated != chunk_hash {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err("chunk hash mismatch")),
        );
    }

    let existed = match state.storage_manager.exists(&chunk_hash).await {
        Ok(exists) => exists,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::err(format!(
                    "failed to check chunk existence: {error}"
                ))),
            );
        }
    };
    let stored = match state
        .storage_manager
        .store(&body, &format!("chunk/{chunk_hash}"))
        .await
    {
        Ok(stored) => stored,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::err(error.to_string())),
            );
        }
    };

    if let Some(pool) = state.db_pool.as_ref() {
        if let Err(error) = sqlx::query(
            r#"
            INSERT INTO chunks (chunk_hash, size_bytes, algo)
            VALUES ($1, $2, 'blake3-v1')
            ON CONFLICT (chunk_hash) DO NOTHING
            "#,
        )
        .bind(&stored.hash)
        .bind(stored.size_bytes as i64)
        .execute(pool)
        .await
        {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::err(format!(
                    "failed to persist chunk metadata: {error}"
                ))),
            );
        }
    }

    (
        StatusCode::OK,
        Json(ApiResponse::ok(UploadChunkResponse {
            chunk_hash: stored.hash,
            size_bytes: stored.size_bytes,
            uploaded: !existed,
        })),
    )
}
