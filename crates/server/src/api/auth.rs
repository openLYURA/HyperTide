//! Authentication API handlers

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::api::common::{map_error, ApiResponse};
use crate::core::auth::{token::TokenPair, AuthManager, Permission};
use crate::AppState;

#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub valid: bool,
    pub owner_id: Option<String>,
    pub permissions: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct GenerateKeyRequest {
    pub owner_id: String,
    pub permissions: Vec<String>,
    pub expires_in_days: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct GenerateKeyResponse {
    pub key: String,
    pub owner_id: String,
    pub permissions: Vec<String>,
    pub expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RevokeKeyRequest {
    pub key: String,
}

#[derive(Debug, Serialize)]
pub struct KeyListItem {
    pub key_prefix: String,
    pub owner_id: String,
    pub permissions: Vec<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub revoked: bool,
}

#[derive(Debug, Deserialize)]
pub struct ExchangeKeyRequest {
    pub api_key: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct RevokeRefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct RevokeRefreshResponse {
    pub revoked: bool,
}

async fn append_auth_event(
    state: &AppState,
    event_type: &str,
    actor_id: &str,
    payload: serde_json::Value,
) {
    if let Some(event_store) = &state.event_store {
        if let Err(error) = event_store
            .append(
                event_type,
                actor_id,
                None,
                None,
                payload,
                &crate::core::events::EventMetadata::default(),
            )
            .await
        {
            tracing::warn!("failed to append auth event {event_type}: {error}");
        }
    }
}

async fn append_auth_audit(
    state: &AppState,
    action: &str,
    actor_id: &str,
    target_id: Option<&str>,
    payload: serde_json::Value,
) {
    if let Some(audit_chain) = &state.audit_chain {
        if let Err(error) = audit_chain
            .append(action, actor_id, None, target_id, payload)
            .await
        {
            tracing::warn!("failed to append auth audit {action}: {error}");
        }
    }
}

fn parse_permission(value: &str) -> Option<Permission> {
    Permission::from_str(value)
}

fn permission_to_string(permission: &Permission) -> String {
    permission.as_str().to_string()
}

async fn require_admin_api_key(
    manager: &AuthManager,
    headers: &axum::http::HeaderMap,
) -> Result<String, (StatusCode, String)> {
    let caller_key = headers
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    let identity = manager
        .validate_api_key_identity(caller_key)
        .await
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid API key".to_string()))?;

    if !identity.has_permission(Permission::Admin) {
        return Err((
            StatusCode::FORBIDDEN,
            "Admin permission required".to_string(),
        ));
    }

    Ok(caller_key.to_string())
}

pub async fn verify_key(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<ApiResponse<VerifyResponse>> {
    let manager = &state.auth_manager;
    let key = headers
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    match manager.validate_key_any(key).await {
        Some(api_key) => Json(ApiResponse::ok(VerifyResponse {
            valid: true,
            owner_id: Some(api_key.owner_id),
            permissions: api_key
                .permissions
                .iter()
                .map(permission_to_string)
                .collect(),
        })),
        None => Json(ApiResponse::ok(VerifyResponse {
            valid: false,
            owner_id: None,
            permissions: vec![],
        })),
    }
}

pub async fn generate_key(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<GenerateKeyRequest>,
) -> (StatusCode, Json<ApiResponse<GenerateKeyResponse>>) {
    let manager = state.auth_manager.clone();
    if let Err((status, message)) = require_admin_api_key(&manager, &headers).await {
        return (status, Json(ApiResponse::err(message)));
    }

    // 输入校验：owner_id 长度和格式
    const MAX_OWNER_ID_LEN: usize = 256;
    if payload.owner_id.len() > MAX_OWNER_ID_LEN {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err("owner_id too long")),
        );
    }
    if !payload
        .owner_id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err(
                "owner_id contains invalid characters",
            )),
        );
    }

    let permissions: Vec<Permission> = payload
        .permissions
        .iter()
        .filter_map(|s| parse_permission(s))
        .collect();

    if permissions.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err("At least one valid permission required")),
        );
    }

    match manager
        .generate_key_persistent(&payload.owner_id, permissions, payload.expires_in_days)
        .await
    {
        Ok(api_key) => {
            append_auth_event(
                &state,
                "KEY_GENERATED",
                &api_key.owner_id,
                json!({
                    "permissions": api_key.permissions.iter().map(permission_to_string).collect::<Vec<_>>(),
                    "expires_at": api_key.expires_at,
                }),
            )
            .await;
            append_auth_audit(
                &state,
                "KEY_GENERATED",
                "admin",
                Some(&api_key.owner_id),
                json!({
                    "permissions": api_key.permissions.iter().map(permission_to_string).collect::<Vec<_>>(),
                    "expires_at": api_key.expires_at,
                }),
            )
            .await;
            (
                StatusCode::CREATED,
                Json(ApiResponse::ok(GenerateKeyResponse {
                    key: api_key.key,
                    owner_id: api_key.owner_id,
                    permissions: api_key
                        .permissions
                        .iter()
                        .map(permission_to_string)
                        .collect(),
                    expires_at: api_key.expires_at.map(|dt| dt.to_rfc3339()),
                })),
            )
        }
        Err(error) => {
            let (status, response) = map_error(error);
            (status, Json(response))
        }
    }
}

pub async fn revoke_key(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<RevokeKeyRequest>,
) -> (StatusCode, Json<ApiResponse<bool>>) {
    let manager = state.auth_manager.clone();
    let caller_key = match require_admin_api_key(&manager, &headers).await {
        Ok(value) => value,
        Err((status, message)) => return (status, Json(ApiResponse::err(message))),
    };

    if caller_key == payload.key {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err("Cannot revoke your own key")),
        );
    }

    if let Some(guard) = &state.high_risk_guard {
        if let Err(message) = guard
            .verify(
                &headers,
                "KEY_REVOKE",
                "admin",
                &json!({
                    "target_key_prefix": payload.key.chars().take(12).collect::<String>(),
                }),
            )
            .await
        {
            return (StatusCode::UNAUTHORIZED, Json(ApiResponse::err(message)));
        }
    }

    match manager.revoke_key_persistent(&payload.key).await {
        Ok(true) => {
            append_auth_event(
                &state,
                "KEY_REVOKED",
                "admin",
                json!({
                    "target_key_prefix": payload.key.chars().take(12).collect::<String>(),
                    "caller_key_prefix": caller_key.chars().take(12).collect::<String>(),
                }),
            )
            .await;
            append_auth_audit(
                &state,
                "KEY_REVOKED",
                "admin",
                Some(&payload.key),
                json!({
                    "target_key_prefix": payload.key.chars().take(12).collect::<String>(),
                    "caller_key_prefix": caller_key.chars().take(12).collect::<String>(),
                }),
            )
            .await;
            (StatusCode::OK, Json(ApiResponse::ok(true)))
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::err("Key not found")),
        ),
        Err(error) => {
            let (status, response) = map_error(error);
            (status, Json(response))
        }
    }
}

pub async fn list_keys(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> (StatusCode, Json<ApiResponse<Vec<KeyListItem>>>) {
    let manager = state.auth_manager.clone();
    if let Err((status, message)) = require_admin_api_key(&manager, &headers).await {
        return (status, Json(ApiResponse::err(message)));
    }

    match manager.list_keys_persistent().await {
        Ok(keys) => {
            let items = keys
                .into_iter()
                .map(|key| KeyListItem {
                    key_prefix: format!("{}...", &key.key[..key.key.len().min(12)]),
                    owner_id: key.owner_id,
                    permissions: key.permissions.iter().map(permission_to_string).collect(),
                    created_at: key.created_at.to_rfc3339(),
                    expires_at: key.expires_at.map(|dt| dt.to_rfc3339()),
                    revoked: key.revoked,
                })
                .collect::<Vec<_>>();
            (StatusCode::OK, Json(ApiResponse::ok(items)))
        }
        Err(error) => {
            let (status, response) = map_error(error);
            (status, Json(response))
        }
    }
}

pub async fn exchange_key(
    State(state): State<AppState>,
    Json(payload): Json<ExchangeKeyRequest>,
) -> (StatusCode, Json<ApiResponse<TokenPair>>) {
    let manager = &state.auth_manager;
    match manager.exchange_key_for_tokens(&payload.api_key).await {
        Ok(tokens) => {
            append_auth_event(
                &state,
                "TOKEN_EXCHANGED",
                "api-key",
                json!({
                    "token_type": tokens.token_type,
                    "expires_in": tokens.expires_in
                }),
            )
            .await;
            (StatusCode::OK, Json(ApiResponse::ok(tokens)))
        }
        Err(error) => {
            let (status, response) = map_error(error);
            (status, Json(response))
        }
    }
}

pub async fn refresh_token(
    State(state): State<AppState>,
    Json(payload): Json<RefreshRequest>,
) -> (StatusCode, Json<ApiResponse<TokenPair>>) {
    let manager = &state.auth_manager;
    match manager.refresh_tokens(&payload.refresh_token).await {
        Ok(tokens) => {
            append_auth_event(
                &state,
                "TOKEN_REFRESHED",
                "refresh-token",
                json!({
                    "token_type": tokens.token_type,
                    "expires_in": tokens.expires_in
                }),
            )
            .await;
            (StatusCode::OK, Json(ApiResponse::ok(tokens)))
        }
        Err(error) => {
            let (status, response) = map_error(error);
            (status, Json(response))
        }
    }
}

pub async fn revoke_refresh_token(
    State(state): State<AppState>,
    Json(payload): Json<RevokeRefreshRequest>,
) -> (StatusCode, Json<ApiResponse<RevokeRefreshResponse>>) {
    let manager = &state.auth_manager;
    match manager.revoke_refresh_token(&payload.refresh_token).await {
        Ok(revoked) => {
            append_auth_event(
                &state,
                "TOKEN_REFRESH_REVOKED",
                "refresh-token",
                json!({
                    "revoked": revoked
                }),
            )
            .await;
            if revoked {
                append_auth_audit(&state, "REFRESH_REVOKED", "refresh-token", None, json!({}))
                    .await;
            }
            (
                StatusCode::OK,
                Json(ApiResponse::ok(RevokeRefreshResponse { revoked })),
            )
        }
        Err(error) => {
            let (status, response) = map_error(error);
            (status, Json(response))
        }
    }
}
