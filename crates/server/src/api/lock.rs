//! Lock API Handlers
//! HTTP endpoints for file locking operations

use crate::api::common::{map_error, ApiResponse};
use crate::api::middleware::authz;
use crate::core::auth::{AuthIdentity, Permission};
use crate::core::lock::FileLock;
use crate::AppState;
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Deserialize)]
pub struct LockRequest {
    pub file_path: String,
    pub owner_id: Option<String>,
    #[serde(default)]
    pub repo_id: String,
    #[serde(default = "default_scope")]
    pub scope: String,
}

#[derive(Debug, Deserialize)]
pub struct UnlockRequest {
    pub file_path: String,
    pub owner_id: Option<String>,
    #[serde(default)]
    pub repo_id: String,
    #[serde(default = "default_scope")]
    pub scope: String,
}

#[derive(Debug, Deserialize)]
pub struct RenewLockRequest {
    pub file_path: String,
    pub owner_id: Option<String>,
    #[serde(default)]
    pub repo_id: String,
    #[serde(default = "default_scope")]
    pub scope: String,
}

#[derive(Debug, Deserialize)]
pub struct ForceUnlockRequest {
    pub file_path: String,
    #[serde(default)]
    pub repo_id: String,
    #[serde(default = "default_scope")]
    pub scope: String,
}

#[derive(Debug, Deserialize)]
pub struct ListLocksQuery {
    pub repo_id: String,
    #[serde(default = "default_scope")]
    pub scope: String,
}

fn default_scope() -> String {
    "asset".to_string()
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

fn validate_lock_target(
    repo_id: &str,
    scope: &str,
    file_path: &str,
) -> Result<(), (StatusCode, String)> {
    let normalized = file_path.replace('\\', "/");
    if repo_id.trim().is_empty()
        || scope.trim().is_empty()
        || normalized.trim().is_empty()
        || normalized.starts_with('/')
        || normalized.contains(':')
        || normalized
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "repo_id, scope, and a safe file_path are required".to_string(),
        ));
    }
    Ok(())
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
    if let Err((status, message)) =
        validate_lock_target(&payload.repo_id, &payload.scope, &payload.file_path)
    {
        return (status, Json(ApiResponse::err(message)));
    }

    let event_meta = crate::core::events::EventMetadata::from_headers(&headers);

    match state
        .lock_manager
        .try_lock_with_repo(
            payload.file_path,
            owner_id,
            &payload.repo_id,
            &payload.scope,
        )
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
                        json!({
                            "file_path": lock.file_path,
                            "repo_id": lock.repo_id,
                            "scope": lock.scope,
                            "lease_expires_at": lock.lease_expires_at,
                        }),
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
) -> (StatusCode, Json<ApiResponse<FileLock>>) {
    let identity = match require_permission(&state, &headers, Permission::Lock).await {
        Ok(identity) => identity,
        Err((status, message)) => return (status, Json(ApiResponse::err(message))),
    };
    let owner_id = match resolve_owner_id(payload.owner_id.as_deref(), &identity) {
        Ok(owner_id) => owner_id,
        Err((status, message)) => return (status, Json(ApiResponse::err(message))),
    };
    if let Err((status, message)) =
        validate_lock_target(&payload.repo_id, &payload.scope, &payload.file_path)
    {
        return (status, Json(ApiResponse::err(message)));
    }

    let event_meta = crate::core::events::EventMetadata::from_headers(&headers);

    match state
        .lock_manager
        .unlock_with_repo(
            &payload.file_path,
            &owner_id,
            &payload.repo_id,
            &payload.scope,
        )
        .await
    {
        Ok(lock) => {
            if let Some(event_store) = &state.event_store {
                if let Err(error) = event_store
                    .append(
                        "LOCK_RELEASED",
                        &owner_id,
                        None,
                        None,
                        json!({
                            "file_path": payload.file_path,
                            "repo_id": payload.repo_id,
                            "scope": payload.scope,
                        }),
                        &event_meta,
                    )
                    .await
                {
                    tracing::warn!("failed to append lock release event: {error}");
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
    if let Err((status, message)) =
        validate_lock_target(&payload.repo_id, &payload.scope, &payload.file_path)
    {
        return (status, Json(ApiResponse::err(message)));
    }

    let event_meta = crate::core::events::EventMetadata::from_headers(&headers);

    match state
        .lock_manager
        .renew_lock_with_repo(
            &payload.file_path,
            &owner_id,
            &payload.repo_id,
            &payload.scope,
        )
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
                        json!({
                            "file_path": payload.file_path,
                            "repo_id": payload.repo_id,
                            "scope": payload.scope,
                            "lease_expires_at": lock.lease_expires_at,
                        }),
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
    if let Err((status, message)) =
        validate_lock_target(&payload.repo_id, &payload.scope, &payload.file_path)
    {
        return (status, Json(ApiResponse::err(message)));
    }
    if let Some(guard) = &state.high_risk_guard {
        if let Err(message) = guard
            .verify(
                &headers,
                "LOCK_FORCE_RELEASE",
                "system-admin",
                &json!({
                    "file_path": payload.file_path,
                    "repo_id": payload.repo_id,
                    "scope": payload.scope,
                }),
            )
            .await
        {
            return (StatusCode::UNAUTHORIZED, Json(ApiResponse::err(message)));
        }
    }

    let event_meta = crate::core::events::EventMetadata::from_headers(&headers);

    match state
        .lock_manager
        .force_unlock_with_repo(&payload.file_path, &payload.repo_id, &payload.scope)
        .await
    {
        Ok(true) => {
            if let Some(event_store) = &state.event_store {
                if let Err(error) = event_store
                    .append(
                        "LOCK_FORCE_RELEASED",
                        "system-admin",
                        None,
                        None,
                        json!({
                            "file_path": payload.file_path,
                            "repo_id": payload.repo_id,
                            "scope": payload.scope,
                        }),
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
                        json!({
                            "file_path": payload.file_path,
                            "repo_id": payload.repo_id,
                            "scope": payload.scope,
                        }),
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
    Query(query): Query<ListLocksQuery>,
) -> (StatusCode, Json<ApiResponse<Vec<FileLock>>>) {
    if let Err((status, message)) = require_permission(&state, &headers, Permission::Lock).await {
        return (status, Json(ApiResponse::err(message)));
    }

    if query.repo_id.trim().is_empty() || query.scope.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err("repo_id and scope are required")),
        );
    }

    let locks = state
        .lock_manager
        .list_locks_with_repo(&query.repo_id, &query.scope);
    (StatusCode::OK, Json(ApiResponse::ok(locks)))
}
