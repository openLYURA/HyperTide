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

/// Both metadata and content must exist before the client can skip an upload.
/// Storage failures are not absence: propagate them instead of requesting a retry
/// that cannot repair an inaccessible storage volume.
async fn find_missing_chunks(
    storage: &StorageManager,
    hashes: Vec<String>,
    indexed: Option<&HashSet<String>>,
) -> Result<Vec<String>, String> {
    let mut missing = Vec::new();
    for hash in hashes {
        let stored = storage.exists(&hash).await?;
        let indexed = indexed.is_none_or(|existing| existing.contains(&hash));
        if !indexed || !stored {
            missing.push(hash);
        }
    }
    Ok(missing)
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

    let mut unique_hashes = payload.chunk_hashes;
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

    let indexed = if let Some(pool) = state.db_pool.as_ref() {
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
            Ok(existing) => Some(existing.into_iter().collect::<HashSet<_>>()),
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
        None
    };
    let missing =
        match find_missing_chunks(&state.storage_manager, unique_hashes, indexed.as_ref()).await {
            Ok(missing) => missing,
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiResponse::err(format!(
                        "failed to check chunk existence: {error}"
                    ))),
                );
            }
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    struct TestStorage {
        root: PathBuf,
        manager: StorageManager,
    }

    impl TestStorage {
        async fn new() -> Self {
            let root = std::env::temp_dir()
                .join(format!("hypertide-missing-chunks-{}", uuid::Uuid::new_v4()));
            let manager = StorageManager::new(&root);
            manager.init().await.expect("init storage");
            Self { root, manager }
        }
    }

    impl Drop for TestStorage {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[tokio::test]
    async fn indexed_but_deleted_chunk_is_requested_again() {
        let storage = TestStorage::new().await;
        let stored = storage
            .manager
            .store(b"chunk", "chunk")
            .await
            .expect("store");
        let indexed = HashSet::from([stored.hash.clone()]);
        let object = storage.manager.get_path(&stored.hash).expect("object path");
        tokio::fs::remove_file(object)
            .await
            .expect("simulate lost object");

        let missing =
            find_missing_chunks(&storage.manager, vec![stored.hash.clone()], Some(&indexed))
                .await
                .expect("find missing chunks");

        assert_eq!(missing, vec![stored.hash]);
    }

    #[tokio::test]
    async fn unindexed_chunk_is_requested_even_when_content_exists() {
        let storage = TestStorage::new().await;
        let stored = storage
            .manager
            .store(b"chunk", "chunk")
            .await
            .expect("store");
        let indexed = HashSet::new();

        let missing =
            find_missing_chunks(&storage.manager, vec![stored.hash.clone()], Some(&indexed))
                .await
                .expect("find missing chunks");

        assert_eq!(missing, vec![stored.hash]);
    }

    #[tokio::test]
    async fn intact_indexed_chunks_do_not_need_retransmission() {
        let storage = TestStorage::new().await;
        let stored = storage
            .manager
            .store(b"chunk", "chunk")
            .await
            .expect("store");
        let indexed = HashSet::from([stored.hash.clone()]);

        let missing = find_missing_chunks(&storage.manager, vec![stored.hash], Some(&indexed))
            .await
            .expect("find missing chunks");

        assert!(missing.is_empty());
    }

    #[tokio::test]
    async fn without_a_database_presence_is_checked_in_storage() {
        let storage = TestStorage::new().await;
        let stored = storage
            .manager
            .store(b"chunk", "chunk")
            .await
            .expect("store");
        let absent = StorageManager::calculate_hash(b"not uploaded");

        let missing =
            find_missing_chunks(&storage.manager, vec![stored.hash, absent.clone()], None)
                .await
                .expect("find missing chunks");

        assert_eq!(missing, vec![absent]);
    }

    #[tokio::test]
    async fn storage_errors_propagate_even_when_chunk_is_unindexed() {
        let storage = TestStorage::new().await;
        let invalid = "not-a-hash".to_string();
        let indexed = HashSet::new();

        let error = find_missing_chunks(&storage.manager, vec![invalid], Some(&indexed))
            .await
            .expect_err("storage errors must propagate before reporting a missing chunk");

        assert!(error.contains("Invalid BLAKE3 hash"));
    }
}
