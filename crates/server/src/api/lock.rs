//! Lock API Handlers
//! HTTP endpoints for file locking operations

use crate::api::common::{map_error, ApiResponse};
use crate::api::middleware::authz;
use crate::core::auth::{AuthIdentity, Permission};
use crate::core::lock::FileLock;
use crate::AppState;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Deserialize)]
pub struct LockRequest {
    pub file_path: String,
    pub owner_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UnlockRequest {
    pub file_path: String,
    pub owner_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RenewLockRequest {
    pub file_path: String,
    pub owner_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ForceUnlockRequest {
    pub file_path: String,
}

async fn require_permission(
    state: &AppState,
    headers: &HeaderMap,
    permission: Permission,
) -> Result<AuthIdentity, (StatusCode, String)> {
    authz::require_permission(state, headers, permission).await
}

fn resolve_owner_id(
    payload_owner_id: Option<&str>,
    identity: &AuthIdentity,
) -> Result<String, (StatusCode, String)> {
    if let Some(owner_id) = payload_owner_id {
        if owner_id != identity.owner_id {
            return Err((StatusCode::FORBIDDEN, "owner_id mismatch".to_string()));
        }
    }
    Ok(identity.owner_id.clone())
}

/// POST /v2/locks/acquire
/// Request a lock on a file
pub async fn lock_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<LockRequest>,
) -> (StatusCode, Json<ApiResponse<FileLock>>) {
    let identity = match require_permission(&state, &headers, Permission::Lock).await {
        Ok(identity) => identity,
        Err((status, message)) => return (status, Json(ApiResponse::err(message))),
    };
    let owner_id = match resolve_owner_id(payload.owner_id.as_deref(), &identity) {
        Ok(owner_id) => owner_id,
        Err((status, message)) => return (status, Json(ApiResponse::err(message))),
    };

    let event_meta = crate::core::events::EventMetadata::from_headers(&headers);

    // 输入校验：file_path 长度和路径穿越检查
    const MAX_FILE_PATH_LEN: usize = 4096;
    if payload.file_path.len() > MAX_FILE_PATH_LEN {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err("file_path too long")),
        );
    }
    if payload.file_path.contains("..") {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err("path traversal not allowed")),
        );
    }

    match state
        .lock_manager
        .try_lock(payload.file_path, owner_id)
        .await
    {
        Ok(lock) => {
            if let Some(event_store) = &state.event_store {
                if let Err(error) = event_store
                    .append(
                        "LOCK_ACQUIRED",
                        &lock.owner_id,
                        None,
                        None,
                        json!({ "file_path": lock.file_path, "lease_expires_at": lock.lease_expires_at }),
                        &event_meta,
                    )
                    .await
                {
                    tracing::warn!("failed to append lock acquire event: {error}");
                }
            }
            (StatusCode::OK, Json(ApiResponse::ok(lock)))
        }
        Err(error) => {
            let (status, response) = map_error(error);
            (status, Json(response))
        }
    }
}

/// DELETE /v2/locks/release
/// Release a lock (only owner can unlock)
pub async fn unlock_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<UnlockRequest>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let identity = match require_permission(&state, &headers, Permission::Lock).await {
        Ok(identity) => identity,
        Err((status, message)) => return (status, Json(ApiResponse::err(message))),
    };
    let owner_id = match resolve_owner_id(payload.owner_id.as_deref(), &identity) {
        Ok(owner_id) => owner_id,
        Err((status, message)) => return (status, Json(ApiResponse::err(message))),
    };

    let event_meta = crate::core::events::EventMetadata::from_headers(&headers);

    // 输入校验：file_path 长度和路径穿越检查
    const MAX_FILE_PATH_LEN: usize = 4096;
    if payload.file_path.len() > MAX_FILE_PATH_LEN {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err("file_path too long")),
        );
    }
    if payload.file_path.contains("..") {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err("path traversal not allowed")),
        );
    }

    match state
        .lock_manager
        .unlock(&payload.file_path, &owner_id)
        .await
    {
        Ok(_) => {
            if let Some(event_store) = &state.event_store {
                if let Err(error) = event_store
                    .append(
                        "LOCK_RELEASED",
                        &owner_id,
                        None,
                        None,
                        json!({ "file_path": payload.file_path }),
                        &event_meta,
                    )
                    .await
                {
                    tracing::warn!("failed to append lock release event: {error}");
                }
            }
            (StatusCode::OK, Json(ApiResponse::ok(())))
        }
        Err(error) => {
            let (status, response) = map_error(error);
            (status, Json(response))
        }
    }
}

/// POST /v2/locks/renew
/// Renew lock lease (owner only)
pub async fn renew_lock_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RenewLockRequest>,
) -> (StatusCode, Json<ApiResponse<FileLock>>) {
    let identity = match require_permission(&state, &headers, Permission::Lock).await {
        Ok(identity) => identity,
        Err((status, message)) => return (status, Json(ApiResponse::err(message))),
    };
    let owner_id = match resolve_owner_id(payload.owner_id.as_deref(), &identity) {
        Ok(owner_id) => owner_id,
        Err((status, message)) => return (status, Json(ApiResponse::err(message))),
    };

    let event_meta = crate::core::events::EventMetadata::from_headers(&headers);

    // 输入校验：file_path 长度和路径穿越检查
    const MAX_FILE_PATH_LEN: usize = 4096;
    if payload.file_path.len() > MAX_FILE_PATH_LEN {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err("file_path too long")),
        );
    }
    if payload.file_path.contains("..") {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err("path traversal not allowed")),
        );
    }

    match state
        .lock_manager
        .renew_lock(&payload.file_path, &owner_id)
        .await
    {
        Ok(lock) => {
            if let Some(event_store) = &state.event_store {
                if let Err(error) = event_store
                    .append(
                        "LOCK_RENEWED",
                        &owner_id,
                        None,
                        None,
                        json!({ "file_path": payload.file_path, "lease_expires_at": lock.lease_expires_at }),
                        &event_meta,
                    )
                    .await
                {
                    tracing::warn!("failed to append lock renew event: {error}");
                }
            }
            (StatusCode::OK, Json(ApiResponse::ok(lock)))
        }
        Err(error) => {
            let (status, response) = map_error(error);
            (status, Json(response))
        }
    }
}

/// POST /v2/locks/force-release
/// Admin force unlock (bypasses ownership check)
pub async fn force_unlock_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ForceUnlockRequest>,
) -> (StatusCode, Json<ApiResponse<bool>>) {
    if let Err((status, message)) = require_permission(&state, &headers, Permission::Admin).await {
        return (status, Json(ApiResponse::err(message)));
    }
    if let Some(guard) = &state.high_risk_guard {
        if let Err(message) = guard
            .verify(
                &headers,
                "LOCK_FORCE_RELEASE",
                "system-admin",
                &json!({ "file_path": payload.file_path }),
            )
            .await
        {
            return (StatusCode::UNAUTHORIZED, Json(ApiResponse::err(message)));
        }
    }

    let event_meta = crate::core::events::EventMetadata::from_headers(&headers);

    // 输入校验：file_path 长度和路径穿越检查
    const MAX_FILE_PATH_LEN: usize = 4096;
    if payload.file_path.len() > MAX_FILE_PATH_LEN {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err("file_path too long")),
        );
    }
    if payload.file_path.contains("..") {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err("path traversal not allowed")),
        );
    }

    match state.lock_manager.force_unlock(&payload.file_path).await {
        Ok(true) => {
            if let Some(event_store) = &state.event_store {
                if let Err(error) = event_store
                    .append(
                        "LOCK_FORCE_RELEASED",
                        "system-admin",
                        None,
                        None,
                        json!({ "file_path": payload.file_path }),
                        &event_meta,
                    )
                    .await
                {
                    tracing::warn!("failed to append lock force-release event: {error}");
                }
            }
            if let Some(audit_chain) = &state.audit_chain {
                if let Err(error) = audit_chain
                    .append(
                        "LOCK_FORCE_RELEASED",
                        "system-admin",
                        None,
                        Some(&payload.file_path),
                        json!({ "file_path": payload.file_path }),
                    )
                    .await
                {
                    tracing::warn!("failed to append force-release audit: {error}");
                }
            }
            (StatusCode::OK, Json(ApiResponse::ok(true)))
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::err("File was not locked")),
        ),
        Err(error) => {
            let (status, response) = map_error(error);
            (status, Json(response))
        }
    }
}

/// GET /v2/locks/acquires
/// List all current locks
pub async fn list_locks(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> (StatusCode, Json<ApiResponse<Vec<FileLock>>>) {
    if let Err((status, message)) = require_permission(&state, &headers, Permission::Lock).await {
        return (status, Json(ApiResponse::err(message)));
    }

    let locks = state.lock_manager.list_locks();
    (StatusCode::OK, Json(ApiResponse::ok(locks)))
}
