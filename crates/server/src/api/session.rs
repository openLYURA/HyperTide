use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;

use crate::api::common::ApiResponse;
use crate::api::middleware::authz;
use crate::core::auth::Permission;
use crate::core::session::{
    AgentSessionRecord, CheckpointAsset, CheckpointPage, CheckpointSnapshot, CreateCheckpointInput,
    CreateSessionInput, SessionCheckpointRecord, SessionError,
};
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct CreateSessionRequest {
    pub repo_id: String,
    pub branch: Option<String>,
    pub base_changeset_id: Option<String>,
    pub workspace_root: String,
    pub intent_id: Option<String>,
    pub task_id: Option<String>,
    pub agent_run_id: Option<String>,
    pub trigger_reason: Option<String>,
    pub risk_level: Option<String>,
    pub semantic_summary: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct CreateCheckpointRequest {
    pub trigger_reason: Option<String>,
    pub semantic_summary: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub assets: Vec<CheckpointAsset>,
}

fn map_session_error(error: SessionError) -> (StatusCode, String) {
    match error {
        SessionError::SessionNotFound { session_id } => (
            StatusCode::NOT_FOUND,
            format!("Session not found: {session_id}"),
        ),
        SessionError::CheckpointNotFound { checkpoint_id } => (
            StatusCode::NOT_FOUND,
            format!("Checkpoint not found: {checkpoint_id}"),
        ),
        SessionError::CheckpointExpired { checkpoint_id } => (
            StatusCode::CONFLICT,
            format!("Checkpoint expired: {checkpoint_id}"),
        ),
    }
}

pub async fn create_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateSessionRequest>,
) -> (StatusCode, Json<ApiResponse<AgentSessionRecord>>) {
    let identity = match authz::require_permission(&state, &headers, Permission::Upload).await {
        Ok(identity) => identity,
        Err((status, message)) => return (status, Json(ApiResponse::err(message))),
    };
    let event_meta = crate::core::events::EventMetadata::from_headers(&headers);

    // 输入校验：workspace_root 长度和路径穿越检查
    const MAX_WORKSPACE_ROOT_LEN: usize = 4096;
    if payload.workspace_root.len() > MAX_WORKSPACE_ROOT_LEN {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err("workspace_root too long")),
        );
    }
    if payload.workspace_root.contains("..") {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err("path traversal not allowed")),
        );
    }

    let record = state.session_manager.create_session(CreateSessionInput {
        repo_id: payload.repo_id,
        branch: payload.branch.unwrap_or_else(|| "main".to_string()),
        base_changeset_id: payload.base_changeset_id,
        workspace_root: payload.workspace_root,
        actor_id: identity.owner_id.clone(),
        intent_id: payload.intent_id,
        task_id: payload.task_id,
        agent_run_id: payload.agent_run_id,
        trigger_reason: payload.trigger_reason,
        risk_level: payload.risk_level,
        semantic_summary: payload.semantic_summary,
        expires_at: payload.expires_at,
    });

    if let Some(event_store) = &state.event_store {
        if let Err(error) = event_store
            .append(
                "SESSION_CREATED",
                &identity.owner_id,
                Some(&record.repo_id),
                None,
                json!({
                    "session_id": record.session_id,
                    "branch": record.branch,
                    "base_changeset_id": record.base_changeset_id,
                    "intent_id": record.intent_id,
                    "task_id": record.task_id,
                    "agent_run_id": record.agent_run_id,
                }),
                &event_meta,
            )
            .await
        {
            tracing::warn!("failed to append session event: {error}");
        }
    }
    if let Some(pool) = &state.db_pool {
        if let Err(error) = sqlx::query(
            r#"
            INSERT INTO agent_sessions (
                session_id, repo_id, branch_name, base_changeset_id, workspace_root, actor_id,
                intent_id, task_id, agent_run_id, trigger_reason, risk_level, semantic_summary,
                expires_at, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            ON CONFLICT (session_id) DO NOTHING
            "#,
        )
        .bind(&record.session_id)
        .bind(&record.repo_id)
        .bind(&record.branch)
        .bind(&record.base_changeset_id)
        .bind(&record.workspace_root)
        .bind(&record.actor_id)
        .bind(&record.intent_id)
        .bind(&record.task_id)
        .bind(&record.agent_run_id)
        .bind(&record.trigger_reason)
        .bind(&record.risk_level)
        .bind(&record.semantic_summary)
        .bind(record.expires_at)
        .bind(record.created_at)
        .execute(pool)
        .await
        {
            tracing::warn!("failed to persist agent session: {error}");
        }
    }

    (StatusCode::CREATED, Json(ApiResponse::ok(record)))
}

async fn create_checkpoint_with_reason(
    state: AppState,
    headers: HeaderMap,
    session_id: String,
    payload: CreateCheckpointRequest,
    default_reason: &'static str,
) -> (StatusCode, Json<ApiResponse<SessionCheckpointRecord>>) {
    let identity = match authz::require_permission(&state, &headers, Permission::Upload).await {
        Ok(identity) => identity,
        Err((status, message)) => return (status, Json(ApiResponse::err(message))),
    };
    let event_meta = crate::core::events::EventMetadata::from_headers(&headers);

    let trigger_reason = payload
        .trigger_reason
        .unwrap_or_else(|| default_reason.to_string());
    let checkpoint = match state
        .session_manager
        .create_checkpoint(CreateCheckpointInput {
            session_id,
            actor_id: identity.owner_id.clone(),
            trigger_reason,
            semantic_summary: payload.semantic_summary,
            expires_at: payload.expires_at,
            assets: payload.assets,
        }) {
        Ok(checkpoint) => checkpoint,
        Err(error) => {
            let (status, message) = map_session_error(error);
            return (status, Json(ApiResponse::err(message)));
        }
    };

    if let Some(event_store) = &state.event_store {
        if let Err(error) = event_store
            .append(
                "SESSION_CHECKPOINT_CREATED",
                &identity.owner_id,
                Some(&checkpoint.repo_id),
                None,
                json!({
                    "session_id": checkpoint.session_id,
                    "checkpoint_id": checkpoint.checkpoint_id,
                    "branch": checkpoint.branch,
                    "base_changeset_id": checkpoint.base_changeset_id,
                    "parent_checkpoint_id": checkpoint.parent_checkpoint_id,
                    "trigger_reason": checkpoint.trigger_reason,
                    "asset_count": checkpoint.assets.len(),
                }),
                &event_meta,
            )
            .await
        {
            tracing::warn!("failed to append checkpoint event: {error}");
        }
    }
    if let Some(pool) = &state.db_pool {
        if let Err(error) = persist_checkpoint(pool, &checkpoint).await {
            tracing::warn!("failed to persist session checkpoint: {error}");
        }
    }

    (StatusCode::CREATED, Json(ApiResponse::ok(checkpoint)))
}

async fn persist_checkpoint(
    pool: &sqlx::PgPool,
    checkpoint: &SessionCheckpointRecord,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        r#"
        INSERT INTO session_checkpoints (
            checkpoint_id, session_id, repo_id, branch_name, base_changeset_id,
            parent_checkpoint_id, workspace_root, actor_id, trigger_reason, intent_id,
            task_id, agent_run_id, risk_level, semantic_summary, expires_at, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
        ON CONFLICT (checkpoint_id) DO NOTHING
        "#,
    )
    .bind(&checkpoint.checkpoint_id)
    .bind(&checkpoint.session_id)
    .bind(&checkpoint.repo_id)
    .bind(&checkpoint.branch)
    .bind(&checkpoint.base_changeset_id)
    .bind(&checkpoint.parent_checkpoint_id)
    .bind(&checkpoint.workspace_root)
    .bind(&checkpoint.actor_id)
    .bind(&checkpoint.trigger_reason)
    .bind(&checkpoint.intent_id)
    .bind(&checkpoint.task_id)
    .bind(&checkpoint.agent_run_id)
    .bind(&checkpoint.risk_level)
    .bind(&checkpoint.semantic_summary)
    .bind(checkpoint.expires_at)
    .bind(checkpoint.created_at)
    .execute(&mut *tx)
    .await?;

    for asset in &checkpoint.assets {
        sqlx::query(
            r#"
            INSERT INTO checkpoint_assets (checkpoint_id, asset_id, path, blob_hash)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (checkpoint_id, asset_id) DO UPDATE
                SET path = EXCLUDED.path,
                    blob_hash = EXCLUDED.blob_hash
            "#,
        )
        .bind(&checkpoint.checkpoint_id)
        .bind(&asset.asset_id)
        .bind(&asset.path)
        .bind(&asset.blob_hash)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(())
}

pub async fn save_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
    Json(payload): Json<CreateCheckpointRequest>,
) -> (StatusCode, Json<ApiResponse<SessionCheckpointRecord>>) {
    create_checkpoint_with_reason(state, headers, session_id, payload, "agent_save").await
}

pub async fn create_checkpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
    Json(payload): Json<CreateCheckpointRequest>,
) -> (StatusCode, Json<ApiResponse<SessionCheckpointRecord>>) {
    create_checkpoint_with_reason(state, headers, session_id, payload, "manual_checkpoint").await
}

pub async fn list_checkpoints(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> (StatusCode, Json<ApiResponse<CheckpointPage>>) {
    if let Err((status, message)) =
        authz::require_permission(&state, &headers, Permission::Download).await
    {
        return (status, Json(ApiResponse::err(message)));
    }

    match state.session_manager.list_checkpoints(&session_id) {
        Ok(page) => (StatusCode::OK, Json(ApiResponse::ok(page))),
        Err(error) => {
            let (status, message) = map_session_error(error);
            (status, Json(ApiResponse::err(message)))
        }
    }
}

pub async fn checkpoint_snapshot(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(checkpoint_id): Path<String>,
) -> (StatusCode, Json<ApiResponse<CheckpointSnapshot>>) {
    if let Err((status, message)) =
        authz::require_permission(&state, &headers, Permission::Download).await
    {
        return (status, Json(ApiResponse::err(message)));
    }

    match state.session_manager.checkpoint_snapshot(&checkpoint_id) {
        Ok(snapshot) => (StatusCode::OK, Json(ApiResponse::ok(snapshot))),
        Err(error) => {
            let (status, message) = map_session_error(error);
            (status, Json(ApiResponse::err(message)))
        }
    }
}
