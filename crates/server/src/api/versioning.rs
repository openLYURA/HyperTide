use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::{Component, Path as FsPath};

use crate::api::common::ApiResponse;
use crate::api::middleware::authz;
use crate::core::auth::{AuthIdentity, Permission};
use crate::core::versioning::{
    AssetDelta, BranchRecord, ChangesetGate, ChangesetKind, ChangesetRecord, ChangesetVisibility,
    HistoryPage, RepoInfo, RepoSummary, SnapshotEntry, SubmitChangesetInput, SyncSnapshot,
    VersioningError, ROOT_BASE_CHANGESET_ID,
};
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct CreateBranchRequest {
    pub repo_id: String,
    pub branch: String,
    pub from_changeset_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateRepoRequest {
    pub repo_id: String,
    pub default_branch: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RepoListResponse {
    pub repos: Vec<RepoSummary>,
}

#[derive(Debug, Serialize)]
pub struct BranchListResponse {
    pub repo_id: String,
    pub branches: Vec<BranchRecord>,
}

#[derive(Debug, Deserialize)]
pub struct SubmitChangesetRequest {
    pub repo_id: String,
    pub branch: Option<String>,
    pub base_changeset_id: Option<String>,
    pub kind: Option<String>,
    pub visibility: Option<String>,
    pub rollback_of: Option<String>,
    pub author: String,
    pub message: String,
    pub intent_id: Option<String>,
    pub task_id: Option<String>,
    pub agent_run_id: Option<String>,
    pub session_id: Option<String>,
    pub parent_checkpoint_id: Option<String>,
    pub risk_level: Option<String>,
    pub semantic_summary: Option<String>,
    pub assets: Vec<AssetDelta>,
}

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    pub branch: Option<String>,
    pub limit: Option<usize>,
    pub cursor: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct RollbackRequest {
    pub repo_id: String,
    pub branch: String,
    pub target_changeset_id: String,
    pub author: String,
    pub message: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RollbackResponse {
    pub rollback_plan: RollbackPlanView,
    pub changeset: ChangesetRecord,
}

#[derive(Debug, Serialize)]
pub struct RollbackPlanView {
    pub base_changeset_id: String,
    pub target_changeset_id: String,
    pub asset_count: usize,
}

#[derive(Debug, Deserialize)]
pub struct SyncQuery {
    pub branch: Option<String>,
    pub to_changeset_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ChangesetActionQuery {
    pub repo_id: String,
}

#[derive(Debug, Serialize)]
pub struct SyncResponse {
    pub repo_id: String,
    pub branch: String,
    pub changeset_id: Option<String>,
    pub assets: Vec<SnapshotEntry>,
}

async fn require_key(
    state: &AppState,
    headers: &HeaderMap,
    permission: Permission,
) -> Result<AuthIdentity, (StatusCode, String)> {
    authz::require_permission(state, headers, permission).await
}

fn parse_kind(value: Option<&str>) -> Result<ChangesetKind, String> {
    match value.unwrap_or("normal").to_lowercase().as_str() {
        "normal" | "direct" | "checkpoint" => Ok(ChangesetKind::Normal),
        "rollback" => Ok(ChangesetKind::Rollback),
        _ => Err("kind must be normal|rollback".to_string()),
    }
}

fn parse_visibility(value: Option<&str>) -> Result<ChangesetVisibility, String> {
    match value.unwrap_or("visible").to_ascii_lowercase().as_str() {
        "visible" => Ok(ChangesetVisibility::Visible),
        "draft" => Ok(ChangesetVisibility::Draft),
        _ => Err("visibility must be visible|draft".to_string()),
    }
}

fn map_versioning_error(error: VersioningError) -> (StatusCode, String) {
    match error {
        VersioningError::RepoAlreadyExists { repo_id } => (
            StatusCode::CONFLICT,
            format!("Repo already exists: {repo_id}"),
        ),
        VersioningError::RepoNotFound { repo_id } => {
            (StatusCode::NOT_FOUND, format!("Repo not found: {repo_id}"))
        }
        VersioningError::BranchNotFound { repo_id, branch } => (
            StatusCode::NOT_FOUND,
            format!("Branch not found: {repo_id}/{branch}"),
        ),
        VersioningError::BranchAlreadyExists { repo_id, branch } => (
            StatusCode::CONFLICT,
            format!("Branch already exists: {repo_id}/{branch}"),
        ),
        VersioningError::ChangesetNotFound {
            repo_id,
            changeset_id,
        } => (
            StatusCode::NOT_FOUND,
            format!("Changeset not found: {repo_id}/{changeset_id}"),
        ),
        VersioningError::BaseChangesetRequired => (
            StatusCode::BAD_REQUEST,
            format!("base_changeset_id is required. use {ROOT_BASE_CHANGESET_ID} for first commit"),
        ),
        VersioningError::BaseChangesetMismatch {
            repo_id,
            branch,
            expected,
            got,
        } => (
            StatusCode::CONFLICT,
            format!(
                "base_changeset_id mismatch for {repo_id}/{branch}, expected={expected:?}, got={got:?}"
            ),
        ),
        VersioningError::InvalidRollbackTarget {
            repo_id,
            branch,
            target_changeset_id,
        } => (
            StatusCode::CONFLICT,
            format!("Rollback target invalid: {repo_id}/{branch}/{target_changeset_id}"),
        ),
        VersioningError::InvalidChangesetState {
            repo_id,
            changeset_id,
            status,
            expected,
        } => (
            StatusCode::CONFLICT,
            format!(
                "Changeset state invalid: repo={repo_id}, changeset={changeset_id}, status={status:?}, expected={expected}"
            ),
        ),
        VersioningError::InvalidAssetLayout { repo_id, message } => (
            StatusCode::BAD_REQUEST,
            format!("Invalid asset layout for {repo_id}: {message}"),
        ),
        VersioningError::Persistence { message } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Versioning persistence failed: {message}"),
        ),
    }
}

fn validate_repo_and_branch(repo_id: &str, branch: &str) -> Result<(), (StatusCode, String)> {
    if repo_id.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "repo_id must not be empty".to_string(),
        ));
    }
    if branch.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "default_branch must not be empty".to_string(),
        ));
    }
    Ok(())
}

fn validate_asset_paths(assets: &[AssetDelta]) -> Result<(), (StatusCode, String)> {
    for asset in assets {
        let normalized = asset.path.replace('\\', "/");
        let path = FsPath::new(&normalized);
        let bytes = normalized.as_bytes();
        let has_windows_drive_prefix =
            bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
        let invalid = normalized.trim().is_empty()
            || normalized.ends_with('/')
            || normalized.contains(':')
            || has_windows_drive_prefix
            || path.is_absolute()
            || path.components().any(|component| {
                matches!(
                    component,
                    Component::CurDir
                        | Component::ParentDir
                        | Component::RootDir
                        | Component::Prefix(_)
                )
            });
        if invalid {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("invalid asset path: {}", asset.path),
            ));
        }
    }
    Ok(())
}

fn ensure_lock_access(
    state: &AppState,
    owner_id: &str,
    repo_id: &str,
    assets: &[AssetDelta],
) -> Result<(), (StatusCode, String)> {
    for asset in assets {
        if let Some(lock) = state
            .lock_manager
            .get_lock_with_repo(repo_id, "asset", &asset.path)
        {
            if lock.owner_id != owner_id {
                return Err((
                    StatusCode::CONFLICT,
                    format!("Lock conflict on {}. owner={}", asset.path, lock.owner_id),
                ));
            }
        }
    }
    Ok(())
}

async fn ensure_blob_exists(
    state: &AppState,
    assets: &[AssetDelta],
) -> Result<(), (StatusCode, String)> {
    for asset in assets {
        if let Some(hash) = &asset.blob_hash {
            if crate::core::storage::StorageManager::validate_hash(hash).is_err() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("Invalid blob hash: {hash}"),
                ));
            }
            match state.storage_manager.exists(hash).await {
                Ok(true) => {}
                Ok(false) => {
                    return Err((StatusCode::BAD_REQUEST, format!("Blob not found: {hash}")));
                }
                Err(error) => {
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to check blob existence: {error}"),
                    ));
                }
            }
        }
    }
    Ok(())
}

/// POST /v2/repos
pub async fn create_repo(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateRepoRequest>,
) -> (StatusCode, Json<ApiResponse<RepoInfo>>) {
    let identity = match require_key(&state, &headers, Permission::Upload).await {
        Ok(key) => key,
        Err((status, message)) => return (status, Json(ApiResponse::err(message))),
    };
    let default_branch = payload.default_branch.unwrap_or_else(|| "main".to_string());

    if let Err((status, message)) = validate_repo_and_branch(&payload.repo_id, &default_branch) {
        return (status, Json(ApiResponse::err(message)));
    }

    match state
        .version_manager
        .create_repo(&payload.repo_id, &default_branch, &identity.owner_id)
        .await
    {
        Ok(repo) => (StatusCode::CREATED, Json(ApiResponse::ok(repo))),
        Err(error) => {
            let (status, message) = map_versioning_error(error);
            (status, Json(ApiResponse::err(message)))
        }
    }
}

/// GET /v2/repos
pub async fn list_repos(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> (StatusCode, Json<ApiResponse<RepoListResponse>>) {
    if let Err((status, message)) = require_key(&state, &headers, Permission::Download).await {
        return (status, Json(ApiResponse::err(message)));
    }

    (
        StatusCode::OK,
        Json(ApiResponse::ok(RepoListResponse {
            repos: state.version_manager.list_repos(),
        })),
    )
}

/// GET /v2/repos/{repo_id}
pub async fn get_repo_info(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(repo_id): Path<String>,
) -> (StatusCode, Json<ApiResponse<RepoInfo>>) {
    if let Err((status, message)) = require_key(&state, &headers, Permission::Download).await {
        return (status, Json(ApiResponse::err(message)));
    }

    match state.version_manager.get_repo_info(&repo_id) {
        Ok(info) => (StatusCode::OK, Json(ApiResponse::ok(info))),
        Err(error) => {
            let (status, message) = map_versioning_error(error);
            (status, Json(ApiResponse::err(message)))
        }
    }
}

/// POST /v2/branches
pub async fn create_branch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateBranchRequest>,
) -> (StatusCode, Json<ApiResponse<BranchRecord>>) {
    let identity = match require_key(&state, &headers, Permission::Upload).await {
        Ok(key) => key,
        Err((status, message)) => return (status, Json(ApiResponse::err(message))),
    };

    if let Err((status, message)) = validate_repo_and_branch(&payload.repo_id, &payload.branch) {
        return (status, Json(ApiResponse::err(message)));
    }

    match state
        .version_manager
        .create_branch(
            &payload.repo_id,
            &payload.branch,
            payload.from_changeset_id.as_deref(),
            &identity.owner_id,
        )
        .await
    {
        Ok(branch) => (StatusCode::CREATED, Json(ApiResponse::ok(branch))),
        Err(error) => {
            let (status, message) = map_versioning_error(error);
            (status, Json(ApiResponse::err(message)))
        }
    }
}

/// GET /v2/branches/{repo_id}
pub async fn list_branches(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(repo_id): Path<String>,
) -> (StatusCode, Json<ApiResponse<BranchListResponse>>) {
    if let Err((status, message)) = require_key(&state, &headers, Permission::Download).await {
        return (status, Json(ApiResponse::err(message)));
    }

    match state.version_manager.list_branches(&repo_id) {
        Ok(branches) => (
            StatusCode::OK,
            Json(ApiResponse::ok(BranchListResponse { repo_id, branches })),
        ),
        Err(error) => {
            let (status, message) = map_versioning_error(error);
            (status, Json(ApiResponse::err(message)))
        }
    }
}

/// POST /v2/changesets
pub async fn submit_changeset(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<SubmitChangesetRequest>,
) -> (StatusCode, Json<ApiResponse<ChangesetRecord>>) {
    let identity = match require_key(&state, &headers, Permission::Upload).await {
        Ok(key) => key,
        Err((status, message)) => return (status, Json(ApiResponse::err(message))),
    };
    let event_meta = crate::core::events::EventMetadata::from_headers(&headers);

    let kind = match parse_kind(payload.kind.as_deref()) {
        Ok(kind) => kind,
        Err(message) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::err(message))),
    };
    let visibility_value = payload
        .visibility
        .as_deref()
        .or_else(|| payload.parent_checkpoint_id.as_ref().map(|_| "draft"));
    let visibility = match parse_visibility(visibility_value) {
        Ok(visibility) => visibility,
        Err(message) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::err(message))),
    };

    if payload.author != identity.owner_id {
        return (
            StatusCode::FORBIDDEN,
            Json(ApiResponse::err("author must match API key owner")),
        );
    }

    let mut assets = payload.assets;
    let checkpoint_snapshot = if let Some(checkpoint_id) = payload.parent_checkpoint_id.as_deref() {
        match state.session_manager.checkpoint_snapshot(checkpoint_id) {
            Ok(snapshot) => {
                let requested_branch = payload.branch.as_deref().unwrap_or("main");
                if payload.repo_id != snapshot.repo_id || requested_branch != snapshot.branch {
                    return (
                        StatusCode::CONFLICT,
                        Json(ApiResponse::err(format!(
                            "checkpoint lineage mismatch: checkpoint={}/{}, request={}/{}",
                            snapshot.repo_id, snapshot.branch, payload.repo_id, requested_branch
                        ))),
                    );
                }
                if payload.base_changeset_id != snapshot.base_changeset_id {
                    return (
                        StatusCode::CONFLICT,
                        Json(ApiResponse::err(format!(
                            "checkpoint base mismatch: checkpoint={:?}, request={:?}",
                            snapshot.base_changeset_id, payload.base_changeset_id
                        ))),
                    );
                }
                Some(snapshot)
            }
            Err(error) => {
                let (status, message) = match error {
                    crate::core::session::SessionError::SessionNotFound { session_id } => (
                        StatusCode::NOT_FOUND,
                        format!("Session not found: {session_id}"),
                    ),
                    crate::core::session::SessionError::CheckpointNotFound { checkpoint_id } => (
                        StatusCode::NOT_FOUND,
                        format!("Checkpoint not found: {checkpoint_id}"),
                    ),
                    crate::core::session::SessionError::CheckpointExpired { checkpoint_id } => (
                        StatusCode::CONFLICT,
                        format!("Checkpoint expired: {checkpoint_id}"),
                    ),
                };
                return (status, Json(ApiResponse::err(message)));
            }
        }
    } else {
        None
    };
    if assets.is_empty() {
        if let Some(snapshot) = &checkpoint_snapshot {
            assets = snapshot
                .assets
                .iter()
                .map(|asset| AssetDelta {
                    asset_id: Some(asset.asset_id.clone()),
                    path: asset.path.clone(),
                    from_blob_hash: None,
                    blob_hash: Some(asset.blob_hash.clone()),
                })
                .collect();
        }
    }

    if let Err(err) = validate_asset_paths(&assets) {
        return (err.0, Json(ApiResponse::err(err.1)));
    }

    if let Err(err) = ensure_lock_access(&state, &identity.owner_id, &payload.repo_id, &assets) {
        return (err.0, Json(ApiResponse::err(err.1)));
    }
    if let Err(err) = ensure_blob_exists(&state, &assets).await {
        return (err.0, Json(ApiResponse::err(err.1)));
    }

    let input = SubmitChangesetInput {
        repo_id: payload.repo_id,
        branch: payload.branch.unwrap_or_else(|| "main".to_string()),
        base_changeset_id: payload.base_changeset_id,
        kind,
        rollback_of: payload.rollback_of,
        author: payload.author,
        message: payload.message,
        visibility,
        intent_id: payload.intent_id,
        task_id: payload.task_id,
        agent_run_id: payload.agent_run_id,
        session_id: payload.session_id.or_else(|| {
            checkpoint_snapshot
                .as_ref()
                .map(|snapshot| snapshot.session_id.clone())
        }),
        parent_checkpoint_id: payload.parent_checkpoint_id,
        risk_level: payload.risk_level,
        semantic_summary: payload.semantic_summary,
        assets,
    };

    match state.version_manager.submit_changeset(input).await {
        Ok(changeset) => {
            if let Some(event_store) = &state.event_store {
                let event_type = match changeset.status {
                    crate::core::versioning::ChangesetStatus::Draft => "CHANGESET_CREATED_DRAFT",
                    _ => "CHANGESET_VISIBLE",
                };
                if let Err(error) = event_store
                    .append(
                        event_type,
                        &identity.owner_id,
                        Some(&changeset.repo_id),
                        Some(&changeset.changeset_id),
                        json!({
                            "branch": changeset.branch,
                            "status": changeset.status,
                            "base_changeset_id": changeset.base_changeset_id,
                            "staging_ref": changeset.staging_ref,
                            "visible_ref": changeset.visible_ref,
                            "intent_id": changeset.intent_id,
                            "task_id": changeset.task_id,
                            "agent_run_id": changeset.agent_run_id,
                            "session_id": changeset.session_id,
                            "parent_checkpoint_id": changeset.parent_checkpoint_id,
                        }),
                        &event_meta,
                    )
                    .await
                {
                    tracing::warn!("failed to append submit changeset event: {error}");
                }
            }
            if let Some(audit_chain) = &state.audit_chain {
                if let Err(error) = audit_chain
                    .append(
                        "CHANGESET_SUBMITTED",
                        &identity.owner_id,
                        Some(&changeset.repo_id),
                        Some(&changeset.changeset_id),
                        json!({
                            "branch": changeset.branch,
                            "status": changeset.status,
                            "base_changeset_id": changeset.base_changeset_id,
                            "staging_ref": changeset.staging_ref,
                            "visible_ref": changeset.visible_ref,
                            "intent_id": changeset.intent_id,
                            "task_id": changeset.task_id,
                            "agent_run_id": changeset.agent_run_id,
                            "session_id": changeset.session_id,
                            "parent_checkpoint_id": changeset.parent_checkpoint_id,
                        }),
                    )
                    .await
                {
                    tracing::warn!("failed to append submit audit: {error}");
                }
            }
            (StatusCode::CREATED, Json(ApiResponse::ok(changeset)))
        }
        Err(error) => {
            let (status, message) = map_versioning_error(error);
            (status, Json(ApiResponse::err(message)))
        }
    }
}

/// GET /v2/history/{repo_id}?branch=...&limit=...&cursor=...
pub async fn list_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(repo_id): Path<String>,
    Query(query): Query<HistoryQuery>,
) -> (StatusCode, Json<ApiResponse<HistoryPage>>) {
    if let Err((status, message)) = require_key(&state, &headers, Permission::Download).await {
        return (status, Json(ApiResponse::err(message)));
    }

    let branch = query.branch.unwrap_or_else(|| "main".to_string());
    let limit = query.limit.unwrap_or(20);
    let cursor = query.cursor.unwrap_or(0);
    match state
        .version_manager
        .history(&repo_id, &branch, limit, cursor)
    {
        Ok(page) => (StatusCode::OK, Json(ApiResponse::ok(page))),
        Err(error) => {
            let (status, message) = map_versioning_error(error);
            (status, Json(ApiResponse::err(message)))
        }
    }
}

/// POST /v2/rollback
pub async fn rollback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RollbackRequest>,
) -> (StatusCode, Json<ApiResponse<RollbackResponse>>) {
    let identity = match require_key(&state, &headers, Permission::Upload).await {
        Ok(key) => key,
        Err((status, message)) => return (status, Json(ApiResponse::err(message))),
    };
    let event_meta = crate::core::events::EventMetadata::from_headers(&headers);
    if payload.author != identity.owner_id {
        return (
            StatusCode::FORBIDDEN,
            Json(ApiResponse::err("author must match API key owner")),
        );
    }
    if let Some(guard) = &state.high_risk_guard {
        if let Err(message) = guard
            .verify(
                &headers,
                "ROLLBACK",
                &identity.owner_id,
                &json!({
                    "repo_id": payload.repo_id,
                    "branch": payload.branch,
                    "target_changeset_id": payload.target_changeset_id,
                }),
            )
            .await
        {
            return (StatusCode::UNAUTHORIZED, Json(ApiResponse::err(message)));
        }
    }

    let plan = match state.version_manager.build_rollback_plan(
        &payload.repo_id,
        &payload.branch,
        &payload.target_changeset_id,
    ) {
        Ok(plan) => plan,
        Err(error) => {
            let (status, message) = map_versioning_error(error);
            return (status, Json(ApiResponse::err(message)));
        }
    };

    if let Err(err) = ensure_lock_access(&state, &identity.owner_id, &payload.repo_id, &plan.assets)
    {
        return (err.0, Json(ApiResponse::err(err.1)));
    }
    if let Err(err) = ensure_blob_exists(&state, &plan.assets).await {
        return (err.0, Json(ApiResponse::err(err.1)));
    }

    let message = payload
        .message
        .unwrap_or_else(|| format!("rollback: {}", payload.target_changeset_id));
    let input = SubmitChangesetInput {
        repo_id: plan.repo_id.clone(),
        branch: plan.branch.clone(),
        base_changeset_id: Some(plan.base_changeset_id.clone()),
        kind: ChangesetKind::Rollback,
        rollback_of: Some(plan.target_changeset_id.clone()),
        author: payload.author,
        message,
        visibility: ChangesetVisibility::Visible,
        intent_id: None,
        task_id: None,
        agent_run_id: None,
        session_id: None,
        parent_checkpoint_id: None,
        risk_level: Some("high".to_string()),
        semantic_summary: Some(format!("formal rollback to {}", plan.target_changeset_id)),
        assets: plan.assets.clone(),
    };

    match state.version_manager.submit_changeset(input).await {
        Ok(changeset) => {
            if let Some(event_store) = &state.event_store {
                if let Err(error) = event_store
                    .append(
                        "ROLLBACK_VISIBLE",
                        &identity.owner_id,
                        Some(&changeset.repo_id),
                        Some(&changeset.changeset_id),
                        json!({
                            "branch": changeset.branch,
                            "target_changeset_id": plan.target_changeset_id,
                        }),
                        &event_meta,
                    )
                    .await
                {
                    tracing::warn!("failed to append rollback event: {error}");
                }
            }
            if let Some(audit_chain) = &state.audit_chain {
                if let Err(error) = audit_chain
                    .append(
                        "ROLLBACK_VISIBLE",
                        &identity.owner_id,
                        Some(&changeset.repo_id),
                        Some(&changeset.changeset_id),
                        json!({
                            "branch": changeset.branch,
                            "target_changeset_id": plan.target_changeset_id,
                        }),
                    )
                    .await
                {
                    tracing::warn!("failed to append rollback audit: {error}");
                }
            }
            (
                StatusCode::CREATED,
                Json(ApiResponse::ok(RollbackResponse {
                    rollback_plan: RollbackPlanView {
                        base_changeset_id: plan.base_changeset_id,
                        target_changeset_id: plan.target_changeset_id,
                        asset_count: plan.assets.len(),
                    },
                    changeset,
                })),
            )
        }
        Err(error) => {
            let (status, message) = map_versioning_error(error);
            (status, Json(ApiResponse::err(message)))
        }
    }
}

/// POST /v2/changesets/{changeset_id}/approve
pub async fn approve_changeset(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(changeset_id): Path<String>,
    Query(query): Query<ChangesetActionQuery>,
) -> (StatusCode, Json<ApiResponse<ChangesetRecord>>) {
    let identity = match require_key(&state, &headers, Permission::Upload).await {
        Ok(key) => key,
        Err((status, message)) => return (status, Json(ApiResponse::err(message))),
    };
    let event_meta = crate::core::events::EventMetadata::from_headers(&headers);

    match state
        .version_manager
        .approve_changeset(&query.repo_id, &changeset_id, &identity.owner_id)
        .await
    {
        Ok(changeset) => {
            if let Some(event_store) = &state.event_store {
                if let Err(error) = event_store
                    .append(
                        "CHANGESET_APPROVED",
                        &identity.owner_id,
                        Some(&changeset.repo_id),
                        Some(&changeset.changeset_id),
                        json!({
                            "branch": changeset.branch,
                            "status": changeset.status,
                            "staging_ref": changeset.staging_ref,
                            "visible_ref": changeset.visible_ref,
                        }),
                        &event_meta,
                    )
                    .await
                {
                    tracing::warn!("failed to append approve event: {error}");
                }
            }
            if let Some(audit_chain) = &state.audit_chain {
                if let Err(error) = audit_chain
                    .append(
                        "CHANGESET_APPROVED",
                        &identity.owner_id,
                        Some(&changeset.repo_id),
                        Some(&changeset.changeset_id),
                        json!({
                            "branch": changeset.branch,
                            "status": changeset.status,
                            "staging_ref": changeset.staging_ref,
                            "visible_ref": changeset.visible_ref,
                        }),
                    )
                    .await
                {
                    tracing::warn!("failed to append approve audit: {error}");
                }
            }
            (StatusCode::OK, Json(ApiResponse::ok(changeset)))
        }
        Err(error) => {
            let (status, message) = map_versioning_error(error);
            (status, Json(ApiResponse::err(message)))
        }
    }
}

/// POST /v2/changesets/{changeset_id}/promote
pub async fn promote_changeset(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(changeset_id): Path<String>,
    Query(query): Query<ChangesetActionQuery>,
) -> (StatusCode, Json<ApiResponse<ChangesetRecord>>) {
    let identity = match require_key(&state, &headers, Permission::Upload).await {
        Ok(key) => key,
        Err((status, message)) => return (status, Json(ApiResponse::err(message))),
    };
    let event_meta = crate::core::events::EventMetadata::from_headers(&headers);
    if let Some(guard) = &state.high_risk_guard {
        if let Err(message) = guard
            .verify(
                &headers,
                "CHANGESET_PROMOTE",
                &identity.owner_id,
                &json!({
                    "repo_id": query.repo_id,
                    "changeset_id": changeset_id,
                }),
            )
            .await
        {
            return (StatusCode::UNAUTHORIZED, Json(ApiResponse::err(message)));
        }
    }

    match state
        .version_manager
        .promote_changeset(&query.repo_id, &changeset_id, &identity.owner_id)
        .await
    {
        Ok(changeset) => {
            if let Some(event_store) = &state.event_store {
                if let Err(error) = event_store
                    .append(
                        "CHANGESET_PROMOTED",
                        &identity.owner_id,
                        Some(&changeset.repo_id),
                        Some(&changeset.changeset_id),
                        json!({
                            "branch": changeset.branch,
                            "status": changeset.status,
                            "promoted_at": changeset.promoted_at,
                            "staging_ref": changeset.staging_ref,
                            "visible_ref": changeset.visible_ref,
                        }),
                        &event_meta,
                    )
                    .await
                {
                    tracing::warn!("failed to append promote event: {error}");
                }
            }
            if let Some(audit_chain) = &state.audit_chain {
                if let Err(error) = audit_chain
                    .append(
                        "CHANGESET_PROMOTED",
                        &identity.owner_id,
                        Some(&changeset.repo_id),
                        Some(&changeset.changeset_id),
                        json!({
                            "branch": changeset.branch,
                            "status": changeset.status,
                            "promoted_at": changeset.promoted_at,
                            "staging_ref": changeset.staging_ref,
                            "visible_ref": changeset.visible_ref,
                        }),
                    )
                    .await
                {
                    tracing::warn!("failed to append promote audit: {error}");
                }
            }
            (StatusCode::OK, Json(ApiResponse::ok(changeset)))
        }
        Err(error) => {
            let (status, message) = map_versioning_error(error);
            (status, Json(ApiResponse::err(message)))
        }
    }
}

/// GET /v2/changesets/{changeset_id}/gate?repo_id=...
pub async fn changeset_gate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(changeset_id): Path<String>,
    Query(query): Query<ChangesetActionQuery>,
) -> (StatusCode, Json<ApiResponse<ChangesetGate>>) {
    if let Err((status, message)) = require_key(&state, &headers, Permission::Download).await {
        return (status, Json(ApiResponse::err(message)));
    }

    match state
        .version_manager
        .changeset_gate(&query.repo_id, &changeset_id)
    {
        Ok(gate) => (StatusCode::OK, Json(ApiResponse::ok(gate))),
        Err(error) => {
            let (status, message) = map_versioning_error(error);
            (status, Json(ApiResponse::err(message)))
        }
    }
}

/// GET /v2/sync/{repo_id}?branch=...&to_changeset_id=...
pub async fn sync_snapshot(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(repo_id): Path<String>,
    Query(query): Query<SyncQuery>,
) -> (StatusCode, Json<ApiResponse<SyncResponse>>) {
    if let Err((status, message)) = require_key(&state, &headers, Permission::Download).await {
        return (status, Json(ApiResponse::err(message)));
    }

    let branch = query.branch.unwrap_or_else(|| "main".to_string());
    let snapshot: SyncSnapshot = match state.version_manager.sync_snapshot(
        &repo_id,
        &branch,
        query.to_changeset_id.as_deref(),
    ) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let (status, message) = map_versioning_error(error);
            return (status, Json(ApiResponse::err(message)));
        }
    };

    (
        StatusCode::OK,
        Json(ApiResponse::ok(SyncResponse {
            repo_id: snapshot.repo_id,
            branch: snapshot.branch,
            changeset_id: snapshot.changeset_id,
            assets: snapshot.assets,
        })),
    )
}
