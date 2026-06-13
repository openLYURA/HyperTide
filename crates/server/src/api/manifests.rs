use std::collections::HashSet;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::Value;

use crate::api::{common::ApiResponse, middleware::authz};
use crate::core::{auth::Permission, storage::StorageManager};
use crate::AppState;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ManifestChunk {
    pub i: u32,
    pub chunk_hash: String,
    pub size: u64,
}

#[derive(Debug, Deserialize)]
pub struct CreateManifestRequest {
    pub version: u32,
    pub chunk_size_policy: String,
    pub chunks: Vec<ManifestChunk>,
    pub file_meta: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct CreateManifestResponse {
    pub manifest_hash: String,
    pub merkle_root: String,
    pub chunk_count: usize,
    pub created: bool,
}

#[derive(Debug, Deserialize)]
pub struct ComposeBlobRequest {
    pub manifest_hash: String,
}

#[derive(Debug, Serialize)]
pub struct ComposeBlobResponse {
    pub blob_hash: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct CanonicalManifest {
    version: u32,
    chunk_size_policy: String,
    chunks: Vec<ManifestChunk>,
    file_meta: Value,
}

async fn require_upload_permission(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, String)> {
    authz::require_permission(state, headers, Permission::Upload)
        .await
        .map(|_| ())
}

fn merkle_root(chunks: &[ManifestChunk]) -> String {
    if chunks.is_empty() {
        return StorageManager::calculate_hash(b"");
    }

    let mut level = chunks
        .iter()
        .map(|chunk| {
            StorageManager::calculate_hash(
                format!("{}:{}:{}", chunk.i, chunk.chunk_hash, chunk.size).as_bytes(),
            )
        })
        .collect::<Vec<_>>();

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = &pair[0];
            let right = pair.get(1).unwrap_or(&pair[0]);
            next.push(StorageManager::calculate_hash(
                format!("{left}{right}").as_bytes(),
            ));
        }
        level = next;
    }

    level
        .pop()
        .unwrap_or_else(|| StorageManager::calculate_hash(b""))
}

async fn load_manifest(
    state: &AppState,
    manifest_hash: &str,
) -> Result<CanonicalManifest, (StatusCode, String)> {
    if let Some(pool) = state.db_pool.as_ref() {
        match sqlx::query_scalar::<_, Value>(
            r#"
            SELECT manifest_json
            FROM manifests
            WHERE manifest_hash = $1
            "#,
        )
        .bind(manifest_hash)
        .fetch_optional(pool)
        .await
        {
            Ok(Some(manifest_json)) => {
                return serde_json::from_value(manifest_json).map_err(|error| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("failed to decode manifest from database: {error}"),
                    )
                });
            }
            Ok(None) => {}
            Err(error) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to read manifest metadata: {error}"),
                ));
            }
        }
    }

    let manifest_bytes = state
        .storage_manager
        .retrieve(manifest_hash)
        .await
        .map_err(|_| {
            (
                StatusCode::NOT_FOUND,
                format!("manifest not found: {manifest_hash}"),
            )
        })?;

    serde_json::from_slice(&manifest_bytes).map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to decode stored manifest: {error}"),
        )
    })
}

pub async fn create_manifest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut payload): Json<CreateManifestRequest>,
) -> (StatusCode, Json<ApiResponse<CreateManifestResponse>>) {
    if let Err((status, message)) = require_upload_permission(&state, &headers).await {
        return (status, Json(ApiResponse::err(message)));
    }
    let event_meta = crate::core::events::EventMetadata::from_headers(&headers);

    if payload.chunks.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err("chunks must not be empty")),
        );
    }
    if payload.chunk_size_policy.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err("chunk_size_policy is required")),
        );
    }

    // 输入校验：chunk_size_policy 长度
    const MAX_CHUNK_SIZE_POLICY_LEN: usize = 64;
    if payload.chunk_size_policy.len() > MAX_CHUNK_SIZE_POLICY_LEN {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err("chunk_size_policy too long")),
        );
    }

    payload.chunks.sort_by_key(|chunk| chunk.i);
    for window in payload.chunks.windows(2) {
        if window[0].i == window[1].i {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::err("duplicate chunk index is not allowed")),
            );
        }
    }

    let chunk_hashes = payload
        .chunks
        .iter()
        .map(|chunk| chunk.chunk_hash.clone())
        .collect::<Vec<_>>();

    let missing = if let Some(pool) = state.db_pool.as_ref() {
        match sqlx::query_scalar::<_, String>(
            r#"
            SELECT chunk_hash
            FROM chunks
            WHERE chunk_hash = ANY($1)
            "#,
        )
        .bind(&chunk_hashes)
        .fetch_all(pool)
        .await
        {
            Ok(existing) => {
                let existing_set: HashSet<String> = existing.into_iter().collect();
                chunk_hashes
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
        for hash in chunk_hashes {
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

    if !missing.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err(format!(
                "manifest references missing chunks: {}",
                missing.join(",")
            ))),
        );
    }

    let canonical = CanonicalManifest {
        version: payload.version,
        chunk_size_policy: payload.chunk_size_policy.clone(),
        chunks: payload.chunks.clone(),
        file_meta: payload.file_meta.unwrap_or(Value::Null),
    };
    let canonical_json = match serde_json::to_vec(&canonical) {
        Ok(data) => data,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::err(format!(
                    "failed to serialize canonical manifest: {error}"
                ))),
            );
        }
    };

    let manifest_hash = StorageManager::calculate_hash(&canonical_json);
    let merkle_root = merkle_root(&canonical.chunks);
    let mut created = match state.storage_manager.exists(&manifest_hash).await {
        Ok(exists) => !exists,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::err(format!(
                    "failed to check manifest existence: {error}"
                ))),
            );
        }
    };

    if let Err(error) = state
        .storage_manager
        .store(&canonical_json, &format!("manifest/{manifest_hash}.json"))
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::err(format!(
                "failed to persist manifest blob: {error}"
            ))),
        );
    }

    if let Some(pool) = state.db_pool.as_ref() {
        match sqlx::query(
            r#"
            INSERT INTO manifests (
                manifest_hash,
                schema_version,
                chunk_size_policy,
                chunk_count,
                manifest_json,
                merkle_root
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (manifest_hash) DO NOTHING
            "#,
        )
        .bind(&manifest_hash)
        .bind(canonical.version as i32)
        .bind(&canonical.chunk_size_policy)
        .bind(canonical.chunks.len() as i32)
        .bind(serde_json::to_value(&canonical).unwrap_or(Value::Null))
        .bind(&merkle_root)
        .execute(pool)
        .await
        {
            Ok(result) => {
                created = created || result.rows_affected() > 0;
            }
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiResponse::err(format!(
                        "failed to persist manifest: {error}"
                    ))),
                );
            }
        }
    }

    (
        StatusCode::CREATED,
        Json(ApiResponse::ok({
            if let Some(event_store) = &state.event_store {
                if let Err(error) = event_store
                    .append(
                        "MANIFEST_CREATED",
                        "manifest-api",
                        None,
                        None,
                        json!({
                            "manifest_hash": manifest_hash,
                            "chunk_count": canonical.chunks.len(),
                            "chunk_size_policy": canonical.chunk_size_policy,
                            "created": created,
                        }),
                        &event_meta,
                    )
                    .await
                {
                    tracing::warn!("failed to append manifest event: {error}");
                }
            }
            CreateManifestResponse {
                manifest_hash,
                merkle_root,
                chunk_count: canonical.chunks.len(),
                created,
            }
        })),
    )
}

pub async fn compose_blob(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ComposeBlobRequest>,
) -> (StatusCode, Json<ApiResponse<ComposeBlobResponse>>) {
    if let Err((status, message)) = require_upload_permission(&state, &headers).await {
        return (status, Json(ApiResponse::err(message)));
    }

    let manifest = match load_manifest(&state, &payload.manifest_hash).await {
        Ok(manifest) => manifest,
        Err((status, message)) => return (status, Json(ApiResponse::err(message))),
    };

    let mut composed = Vec::new();
    let mut total_size: u64 = 0;
    for chunk in manifest.chunks {
        let bytes = match state.storage_manager.retrieve(&chunk.chunk_hash).await {
            Ok(bytes) => bytes,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ApiResponse::err(format!(
                        "manifest references missing chunk: {}",
                        chunk.chunk_hash
                    ))),
                );
            }
        };
        if bytes.len() as u64 != chunk.size {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::err(format!(
                    "chunk size mismatch for {}: manifest declared {} but actual {}",
                    chunk.chunk_hash,
                    chunk.size,
                    bytes.len()
                ))),
            );
        }
        total_size += bytes.len() as u64;
        composed.extend_from_slice(&bytes);
    }

    let stored = match state
        .storage_manager
        .store(
            &composed,
            &format!("blob-from-manifest/{}", payload.manifest_hash),
        )
        .await
    {
        Ok(stored) => stored,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::err(format!("failed to compose blob: {error}"))),
            );
        }
    };

    (
        StatusCode::OK,
        Json(ApiResponse::ok(ComposeBlobResponse {
            blob_hash: stored.hash,
            size_bytes: total_size,
        })),
    )
}
