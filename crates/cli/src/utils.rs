use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use blake3::Hasher;
use reqwest::{multipart, RequestBuilder, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::workspace;

// ── Constants ──

pub(crate) const ROOT_BASE_CHANGESET_ID: &str = "ROOT";
pub(crate) const DIRECT_UPLOAD_THRESHOLD_BYTES: usize = 8 * 1024 * 1024;
pub(crate) static NONCE_COUNTER: AtomicU64 = AtomicU64::new(1);
static JSON_OUTPUT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub(crate) fn set_json_output(enabled: bool) {
    JSON_OUTPUT.store(enabled, std::sync::atomic::Ordering::Relaxed);
}

pub(crate) fn json_output_enabled() -> bool {
    JSON_OUTPUT.load(std::sync::atomic::Ordering::Relaxed)
}

// ── Types ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CliProfile {
    pub server: String,
    #[serde(alias = "token")]
    pub api_key: String,
    #[serde(default)]
    pub api_key_direct: bool,
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub access_token_expires_at: Option<i64>,
    pub current_repo: Option<String>,
    #[serde(default = "default_branch")]
    pub current_branch: String,
}

pub(crate) fn default_branch() -> String {
    "main".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct StageFile {
    pub branch: String,
    pub base_changeset_id: Option<String>,
    pub assets: Vec<AssetDelta>,
}

impl StageFile {
    pub(crate) fn default_for_branch(branch: &str) -> Self {
        Self {
            branch: branch.to_string(),
            base_changeset_id: None,
            assets: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AssetDelta {
    pub path: String,
    pub blob_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct WorkspaceFile {
    pub path: String,
    pub blob_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WorkspaceState {
    pub repo_id: String,
    pub branch: String,
    pub workspace_root: String,
    pub base_changeset_id: Option<String>,
    pub checked_out_assets: Vec<WorkspaceFile>,
    pub last_synced_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct SessionState {
    pub current_session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct FileLockInfo {
    pub file_path: String,
    pub owner_id: String,
    pub locked_at: String,
    pub lease_expires_at: Option<String>,
    #[serde(default)]
    pub repo_id: String,
    #[serde(default = "default_lock_scope")]
    pub scope: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct LockRequest<'a> {
    pub file_path: &'a str,
    pub repo_id: &'a str,
    pub scope: &'a str,
}

fn default_lock_scope() -> String {
    "asset".to_string()
}

#[derive(Debug, Serialize)]
pub(crate) struct AttestRequest<'a> {
    pub witness_id: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ComposeBlobRequest<'a> {
    pub manifest_hash: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ComposeBlobResponse {
    pub blob_hash: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AssetStatusKind {
    Unmodified,
    Modified,
    Added,
    Deleted,
    Staged,
    LockedByOther,
    StaleBase,
}

impl AssetStatusKind {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Unmodified => "unmodified",
            Self::Modified => "modified",
            Self::Added => "added",
            Self::Deleted => "deleted",
            Self::Staged => "staged",
            Self::LockedByOther => "locked_by_other",
            Self::StaleBase => "stale_base",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<ApiError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ApiError {
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub details: Option<serde_json::Value>,
    pub request_id: String,
}

pub(crate) struct HttpResponse<T> {
    pub status: StatusCode,
    pub payload: ApiResponse<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct VerifyResponse {
    pub valid: bool,
    pub owner_id: Option<String>,
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BranchRecord {
    pub name: String,
    pub created_by: String,
    pub created_at: String,
    pub is_default: bool,
    pub head_changeset_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BranchListResponse {
    pub repo_id: String,
    pub branches: Vec<BranchRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RepoSummary {
    pub repo_id: String,
    pub default_branch: String,
    pub branch_count: usize,
    pub default_head_changeset_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RepoInfo {
    pub repo_id: String,
    pub default_branch: String,
    pub branch_count: usize,
    pub default_head_changeset_id: Option<String>,
    pub branches: Vec<BranchRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RepoListResponse {
    pub repos: Vec<RepoSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ChangesetRecord {
    pub changeset_id: String,
    pub repo_id: String,
    pub branch: String,
    pub parent_changeset_id: Option<String>,
    pub base_changeset_id: Option<String>,
    pub kind: String,
    pub rollback_of: Option<String>,
    pub author: String,
    pub message: String,
    pub created_at: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub staging_ref: Option<String>,
    #[serde(default)]
    pub visible_ref: Option<String>,
    pub assets: Vec<AssetDelta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ChangesetGate {
    pub repo_id: String,
    pub changeset_id: String,
    pub branch: String,
    pub status: String,
    pub required_state: String,
    pub can_promote: bool,
    pub blocking_reason: Option<String>,
    pub base_changeset_id: Option<String>,
    pub branch_head_changeset_id: Option<String>,
    pub staging_ref: Option<String>,
    pub visible_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HistoryPage {
    pub items: Vec<ChangesetRecord>,
    pub next_cursor: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SyncResponse {
    pub repo_id: String,
    pub branch: String,
    pub changeset_id: Option<String>,
    pub assets: Vec<SyncAsset>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SyncAsset {
    #[serde(default)]
    pub asset_id: Option<String>,
    pub path: String,
    pub blob_hash: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct CreateBranchRequest<'a> {
    pub repo_id: &'a str,
    pub branch: &'a str,
    pub from_changeset_id: Option<&'a str>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CreateRepoRequest<'a> {
    pub repo_id: &'a str,
    pub default_branch: &'a str,
}

#[derive(Debug, Serialize)]
pub(crate) struct SubmitRequest<'a> {
    pub repo_id: &'a str,
    pub branch: &'a str,
    pub base_changeset_id: &'a str,
    pub kind: &'a str,
    pub visibility: Option<&'a str>,
    pub rollback_of: Option<&'a str>,
    pub author: &'a str,
    pub message: &'a str,
    pub intent_id: Option<&'a str>,
    pub task_id: Option<&'a str>,
    pub agent_run_id: Option<&'a str>,
    pub session_id: Option<&'a str>,
    pub parent_checkpoint_id: Option<&'a str>,
    pub risk_level: Option<&'a str>,
    pub semantic_summary: Option<&'a str>,
    pub assets: &'a [AssetDelta],
}

#[derive(Debug, Serialize)]
pub(crate) struct CreateSessionRequest<'a> {
    pub repo_id: &'a str,
    pub branch: &'a str,
    pub base_changeset_id: Option<&'a str>,
    pub workspace_root: &'a str,
    pub trigger_reason: &'a str,
    pub semantic_summary: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AgentSessionRecord {
    pub session_id: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct CreateCheckpointRequest<'a> {
    pub trigger_reason: &'a str,
    pub semantic_summary: Option<&'a str>,
    pub assets: &'a [CheckpointAsset],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CheckpointAsset {
    pub asset_id: String,
    pub path: String,
    pub blob_hash: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub(crate) struct SessionCheckpointRecord {
    pub checkpoint_id: String,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub base_changeset_id: Option<String>,
    #[serde(default)]
    pub trigger_reason: Option<String>,
    #[serde(default)]
    pub semantic_summary: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub assets: Vec<CheckpointAsset>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CheckpointPage {
    pub items: Vec<SessionCheckpointRecord>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub(crate) struct CheckpointSnapshot {
    pub checkpoint_id: String,
    pub session_id: String,
    pub repo_id: String,
    pub branch: String,
    pub base_changeset_id: Option<String>,
    pub workspace_root: String,
    pub assets: Vec<CheckpointAsset>,
}

#[derive(Debug, Serialize)]
pub(crate) struct RollbackRequest<'a> {
    pub repo_id: &'a str,
    pub branch: &'a str,
    pub target_changeset_id: &'a str,
    pub author: &'a str,
    pub message: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MissingChunksRequest<'a> {
    pub chunk_hashes: &'a [String],
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct MissingChunksResponse {
    pub missing: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ManifestChunk {
    pub i: usize,
    pub chunk_hash: String,
    pub size: usize,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CreateManifestRequest<'a> {
    pub version: u32,
    pub chunk_size_policy: &'a str,
    pub chunks: &'a [ManifestChunk],
    pub file_meta: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct CreateManifestResponse {
    pub manifest_hash: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ExchangeKeyRequest<'a> {
    pub api_key: &'a str,
}

#[derive(Debug, Serialize)]
pub(crate) struct RefreshRequest<'a> {
    pub refresh_token: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct UploadResponse {
    pub hash: String,
    pub size_bytes: u64,
    pub original_path: String,
}

#[derive(Debug, Clone)]
pub(crate) struct HighRiskHeaders {
    pub nonce: String,
    pub timestamp: i64,
    pub signature: String,
}

#[derive(Debug)]
pub(crate) struct AssetRow {
    pub path: String,
    pub base_hash: Option<String>,
    pub local_hash: Option<String>,
    pub staged_hash: Option<String>,
}

#[allow(dead_code)]
pub(crate) struct ConflictEntry {
    pub path: String,
    pub base_hash: String,
    pub local_hash: Option<String>,
}

pub(crate) struct StorageHash;

impl StorageHash {
    pub(crate) fn hash_bytes(bytes: &[u8]) -> String {
        let mut hasher = Hasher::new();
        hasher.update(bytes);
        hasher.finalize().to_hex().to_string()
    }
}

// ── State helpers ──

pub(crate) fn resolve_repo(profile: &CliProfile, repo: Option<&str>) -> Result<String> {
    if let Some(repo) = repo {
        return Ok(repo.to_string());
    }
    profile
        .current_repo
        .clone()
        .ok_or_else(|| anyhow!("repo not set. pass --repo or run login with --repo"))
}

pub(crate) fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

pub(crate) fn token_expired(profile: &CliProfile) -> bool {
    let Some(expires_at) = profile.access_token_expires_at else {
        return true;
    };
    now_unix() >= expires_at.saturating_sub(30)
}

pub(crate) fn apply_token_pair(profile: &mut CliProfile, pair: TokenPair) {
    profile.access_token = Some(pair.access_token);
    profile.refresh_token = Some(pair.refresh_token);
    profile.access_token_expires_at = Some(now_unix() + pair.expires_in.max(0));
}

pub(crate) fn state_paths() -> Result<workspace::StatePaths> {
    Ok(workspace::state_paths_from(&std::env::current_dir()?))
}

pub(crate) fn load_profile() -> Result<CliProfile> {
    let paths = state_paths()?;
    workspace::load_json(&paths.profile_path)
}

pub(crate) fn save_profile(profile: &CliProfile) -> Result<()> {
    let paths = state_paths()?;
    workspace::ensure_state_dirs(&paths)?;
    workspace::save_json(&paths.profile_path, profile)
}

pub(crate) fn load_stage() -> Result<StageFile> {
    let paths = state_paths()?;
    workspace::load_json(&paths.stage_path)
}

pub(crate) fn save_stage(stage: &StageFile) -> Result<()> {
    let paths = state_paths()?;
    workspace::ensure_state_dirs(&paths)?;
    workspace::save_json(&paths.stage_path, stage)
}

pub(crate) fn load_workspace() -> Result<WorkspaceState> {
    let paths = state_paths()?;
    workspace::load_json(&paths.workspace_path)
}

pub(crate) fn save_workspace(ws: &WorkspaceState) -> Result<()> {
    let paths = state_paths()?;
    workspace::ensure_state_dirs(&paths)?;
    workspace::save_json(&paths.workspace_path, ws)
}

pub(crate) fn load_session_state() -> Result<SessionState> {
    let paths = state_paths()?;
    let path = paths.state_dir.join("session.json");
    let content =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let session: SessionState = serde_json::from_str(&content)?;
    Ok(session)
}

pub(crate) fn save_session_state(session: &SessionState) -> Result<()> {
    let paths = state_paths()?;
    workspace::ensure_state_dirs(&paths)?;
    let path = paths.state_dir.join("session.json");
    workspace::save_json(&path, session)
}

#[expect(dead_code)]
pub(crate) fn ensure_state_dir() -> Result<()> {
    let paths = state_paths()?;
    workspace::ensure_state_dirs(&paths)?;
    Ok(())
}

pub(crate) fn cache_object_path(hash: &str) -> Result<PathBuf> {
    validate_blake3_hash(hash)?;
    let paths = state_paths()?;
    Ok(workspace::cache_object_path(&paths, hash))
}

pub(crate) fn cache_blob(hash: &str, bytes: &[u8]) -> Result<()> {
    let paths = state_paths()?;
    workspace::ensure_state_dirs(&paths)?;
    let path = workspace::cache_object_path(&paths, hash);
    fs::write(&path, bytes)
        .with_context(|| format!("failed to write cached blob {}", path.display()))?;
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn _is_inside(path: &Path, maybe_parent: &Path) -> bool {
    path.starts_with(maybe_parent)
}

// ── Asset helpers ──

pub(crate) fn normalize_asset_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

pub(crate) fn confirm_dangerous(action: &str, yes: bool) -> Result<()> {
    if yes {
        return Ok(());
    }
    eprint!("dangerous operation: {}. confirm? [y/N] ", action);
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim().to_lowercase() != "y" {
        eprintln!("cancelled.");
        std::process::exit(0);
    }
    Ok(())
}

pub(crate) fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}

pub(crate) fn hash_local_asset(workspace_root: &Path, asset_path: &str) -> Result<Option<String>> {
    let target = resolve_workspace_target(workspace_root, asset_path)?;
    if !target.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&target)
        .with_context(|| format!("failed to read workspace file {}", target.display()))?;
    Ok(Some(StorageHash::hash_bytes(&bytes)))
}

pub(crate) fn detect_local_modifications(workspace: &WorkspaceState) -> Result<Vec<ConflictEntry>> {
    let workspace_root = Path::new(&workspace.workspace_root);
    let mut conflicts = Vec::new();
    for asset in &workspace.checked_out_assets {
        let local_hash = hash_local_asset(workspace_root, &asset.path)?;
        if local_hash.as_deref() != Some(asset.blob_hash.as_str()) {
            conflicts.push(ConflictEntry {
                path: asset.path.clone(),
                base_hash: asset.blob_hash.clone(),
                local_hash,
            });
        }
    }
    Ok(conflicts)
}

pub(crate) fn upsert_stage_asset(
    stage: &mut StageFile,
    path: &str,
    blob_hash: Option<String>,
    asset_id: Option<String>,
) {
    if let Some(existing) = stage.assets.iter_mut().find(|asset| asset.path == path) {
        existing.blob_hash = blob_hash;
        if asset_id.is_some() {
            existing.asset_id = asset_id;
        }
    } else {
        stage.assets.push(AssetDelta {
            path: path.to_string(),
            blob_hash,
            asset_id,
        });
    }
}

pub(crate) fn classify_asset_status(
    base_hash: Option<&str>,
    local_hash: Option<&str>,
    staged_hash: Option<&str>,
    lock_owner: Option<&str>,
    stale_base: bool,
) -> AssetStatusKind {
    if staged_hash.is_some() {
        return AssetStatusKind::Staged;
    }
    if lock_owner.is_some() {
        return AssetStatusKind::LockedByOther;
    }
    if stale_base {
        return AssetStatusKind::StaleBase;
    }
    match (base_hash, local_hash, staged_hash) {
        (_, _, Some(_)) => AssetStatusKind::Staged,
        (Some(_), None, None) => AssetStatusKind::Deleted,
        (Some(base), Some(local), None) if base != local => AssetStatusKind::Modified,
        (None, Some(_), None) => AssetStatusKind::Added,
        _ => AssetStatusKind::Unmodified,
    }
}

pub(crate) fn collect_asset_rows(
    workspace: &WorkspaceState,
    stage: &StageFile,
) -> Result<Vec<AssetRow>> {
    let workspace_root = PathBuf::from(&workspace.workspace_root);
    let mut paths = workspace
        .checked_out_assets
        .iter()
        .map(|asset| asset.path.clone())
        .collect::<HashSet<_>>();
    for asset in &stage.assets {
        paths.insert(asset.path.clone());
    }

    let mut rows = paths
        .into_iter()
        .map(|path| {
            let base_hash = workspace
                .checked_out_assets
                .iter()
                .find(|asset| asset.path == path)
                .map(|asset| asset.blob_hash.clone());
            let staged_hash = stage
                .assets
                .iter()
                .find(|asset| asset.path == path)
                .and_then(|asset| asset.blob_hash.clone());
            let local_hash = hash_local_asset(&workspace_root, &path)?;
            Ok(AssetRow {
                path,
                base_hash,
                local_hash,
                staged_hash,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    rows.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(rows)
}

pub(crate) fn collect_workspace_checkpoint_assets(
    workspace: &WorkspaceState,
) -> Result<Vec<CheckpointAsset>> {
    let workspace_root = PathBuf::from(&workspace.workspace_root);
    workspace
        .checked_out_assets
        .iter()
        .map(|asset| {
            let target = resolve_workspace_target(&workspace_root, &asset.path)?;
            let bytes = fs::read(&target)
                .with_context(|| format!("failed to read {}", target.display()))?;
            Ok(CheckpointAsset {
                asset_id: asset.asset_id.clone().unwrap_or_else(|| asset.path.clone()),
                path: asset.path.clone(),
                blob_hash: hash_bytes(&bytes),
            })
        })
        .collect()
}

#[allow(dead_code)]
pub(crate) fn checkpoint_assets_to_deltas(assets: &[CheckpointAsset]) -> Vec<AssetDelta> {
    assets
        .iter()
        .map(|asset| AssetDelta {
            path: asset.path.clone(),
            blob_hash: Some(asset.blob_hash.clone()),
            asset_id: Some(asset.asset_id.clone()),
        })
        .collect()
}

pub(crate) fn resolve_workspace_target(workspace_root: &Path, asset_path: &str) -> Result<PathBuf> {
    let normalized = asset_path.replace('/', std::path::MAIN_SEPARATOR_STR);
    let candidate = PathBuf::from(&normalized);
    let raw = asset_path.replace('\\', "/");
    let bytes = raw.as_bytes();
    let has_windows_drive_prefix =
        bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    if candidate.is_absolute() || has_windows_drive_prefix {
        return Err(anyhow!(
            "checkpoint asset path must be relative: {asset_path}"
        ));
    }
    let has_parent = candidate
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir));
    if has_parent {
        return Err(anyhow!(
            "checkpoint asset path escapes workspace: {asset_path}"
        ));
    }
    let target = workspace_root.join(candidate);
    if !_is_inside(&target, workspace_root) {
        return Err(anyhow!(
            "checkpoint asset path escapes workspace: {asset_path}"
        ));
    }
    let mut current = workspace_root.to_path_buf();
    for component in target
        .strip_prefix(workspace_root)
        .with_context(|| format!("asset path escapes workspace: {asset_path}"))?
        .components()
    {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(anyhow!(
                    "asset path traverses a symbolic link: {asset_path}"
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect {}", current.display()));
            }
        }
    }
    Ok(target)
}

pub(crate) fn validate_blake3_hash(hash: &str) -> Result<()> {
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "invalid BLAKE3 hash: expected 64 hexadecimal characters"
        ));
    }
    Ok(())
}

// ── Print helpers ──

pub(crate) fn print_changeset_action(action: &str, changeset: &ChangesetRecord) {
    println!(
        "changeset {}: {} status={} branch={} staging_ref={} visible_ref={}",
        action,
        changeset.changeset_id,
        changeset.status.as_deref().unwrap_or("<unknown>"),
        changeset.branch,
        changeset.staging_ref.as_deref().unwrap_or("<none>"),
        changeset.visible_ref.as_deref().unwrap_or("<none>")
    );
}

pub(crate) fn print_lock(label: &str, lock: &FileLockInfo) {
    println!(
        "{}: {} repo={} scope={} owner={} locked_at={} lease_expires_at={}",
        label,
        lock.file_path,
        if lock.repo_id.is_empty() {
            "<default>"
        } else {
            &lock.repo_id
        },
        lock.scope,
        lock.owner_id,
        lock.locked_at,
        lock.lease_expires_at.as_deref().unwrap_or("<none>")
    );
}

pub(crate) fn print_json_response(
    response: ApiResponse<serde_json::Value>,
    fallback: &str,
) -> Result<()> {
    if !response.success {
        return Err(anyhow!(api_error_message(&response, fallback)));
    }
    let data = response.data.context("missing response data")?;
    println!("{}", serde_json::to_string_pretty(&data)?);
    Ok(())
}

pub(crate) fn push_query_param<T: ToString>(
    path: &mut String,
    sep: &mut char,
    key: &str,
    value: Option<T>,
) {
    let Some(value) = value else {
        return;
    };
    path.push(*sep);
    *sep = '&';
    path.push_str(key);
    path.push('=');
    path.push_str(&value.to_string());
}

// ── API / HTTP helpers ──

pub(crate) fn with_auth(request: RequestBuilder, profile: &CliProfile) -> RequestBuilder {
    if profile.api_key_direct {
        return request.header("X-API-Key", &profile.api_key);
    }
    if let Some(access_token) = profile.access_token.as_deref() {
        return request.bearer_auth(access_token);
    }
    request.header("X-API-Key", &profile.api_key)
}

pub(crate) fn api_error_message<T>(response: &ApiResponse<T>, fallback: &str) -> String {
    response
        .error
        .as_ref()
        .map(friendly_error)
        .unwrap_or_else(|| fallback.to_string())
}

pub(crate) fn friendly_error(err: &ApiError) -> String {
    match err.code.as_str() {
        "conflict" if err.message.contains("locked by") => {
            let owner = err.message.split("locked by ").nth(1).unwrap_or("unknown");
            format!(
                "文件已被 {} 锁定。\n\
                 使用 'ht lock list' 查看所有锁。\n\
                 使用 'ht lock release --path <path>' 释放锁。",
                owner
            )
        }
        "conflict" if err.message.contains("BaseChangesetMismatch") => {
            "本地基线已过期。请先执行 'ht sync' 更新基线。".to_string()
        }
        "validation_error" if err.message.contains("nothing staged") => {
            "暂存区为空。请先执行 'ht add --file <file>' 暂存文件。".to_string()
        }
        "UNAUTHORIZED" | "unauthorized" => {
            "认证失败。请检查 API Key 或重新执行 'ht login'。".to_string()
        }
        "FORBIDDEN" | "forbidden" => "权限不足。请联系仓库管理员。".to_string(),
        _ => format!("[{}] {}", err.code, err.message),
    }
}

pub(crate) fn submit_error_message<T>(response: &ApiResponse<T>) -> String {
    let message = api_error_message(response, "submit failed");
    if message.contains("Lock conflict") {
        return format!("submit failed: lock conflict: {message}");
    }
    if message.contains("base_changeset_id mismatch") {
        return format!("submit failed: stale base snapshot: {message}");
    }
    if message.contains("Blob not found") {
        return format!("submit failed: missing blob: {message}");
    }
    if message.contains("UNAUTHORIZED") || message.contains("FORBIDDEN") {
        return format!("submit failed: authentication/authorization error: {message}");
    }
    message
}

pub(crate) async fn send_authed_api<T: DeserializeOwned, F>(
    client: &reqwest::Client,
    profile: &mut CliProfile,
    build_request: F,
    context: &str,
) -> Result<ApiResponse<T>>
where
    F: Fn(&reqwest::Client, &CliProfile) -> RequestBuilder,
{
    ensure_access_token(client, profile).await?;

    let session_id = load_session_state().ok().and_then(|s| s.current_session_id);

    let mut response: HttpResponse<T> = {
        let req = build_request(client, profile);
        let req = req.header("X-HT-Tool-Id", "ht-cli");
        let req = if let Some(ref sid) = session_id {
            req.header("X-HT-Session-Id", sid.as_str())
        } else {
            req
        };
        execute_api(req, context).await?
    };
    if !profile.api_key_direct && response.status == StatusCode::UNAUTHORIZED {
        refresh_access_token(client, profile)
            .await
            .map_err(|error| anyhow!("{error}. please run `ht login --server ... --token ...`"))?;
        let req = build_request(client, profile);
        let req = req.header("X-HT-Tool-Id", "ht-cli");
        let req = if let Some(ref sid) = session_id {
            req.header("X-HT-Session-Id", sid.as_str())
        } else {
            req
        };
        response = execute_api(req, context).await?;
    }
    Ok(response.payload)
}

pub(crate) async fn execute_api<T: DeserializeOwned>(
    request: reqwest::RequestBuilder,
    context: &str,
) -> Result<HttpResponse<T>> {
    let response = request.send().await?;
    let status = response.status();
    let body = response.text().await?;

    match serde_json::from_str::<ApiResponse<T>>(&body) {
        Ok(payload) => Ok(HttpResponse { status, payload }),
        Err(_) => Err(anyhow!(
            "{}: HTTP {} with non-JSON response body: {}",
            context,
            status,
            summarize_body(&body)
        )),
    }
}

pub(crate) fn summarize_body(body: &str) -> String {
    let compact = body.trim().replace('\n', " ");
    if compact.is_empty() {
        return "<empty>".to_string();
    }
    if compact.chars().count() > 200 {
        let preview: String = compact.chars().take(200).collect();
        return format!("{}...", preview);
    }
    compact
}

pub(crate) async fn exchange_api_key_for_tokens(
    client: &reqwest::Client,
    profile: &mut CliProfile,
) -> Result<()> {
    let url = format!(
        "{}/v2/auth/exchange-key",
        profile.server.trim_end_matches('/')
    );
    let payload = ExchangeKeyRequest {
        api_key: &profile.api_key,
    };
    let response: HttpResponse<TokenPair> = execute_api(
        client.post(url).json(&payload),
        "exchange-key response decode failed",
    )
    .await?;
    if !response.payload.success {
        return Err(anyhow!(
            "{}",
            api_error_message(&response.payload, "exchange-key failed")
        ));
    }
    let token_pair = response
        .payload
        .data
        .context("missing token pair in exchange-key response")?;
    apply_token_pair(profile, token_pair);
    Ok(())
}

pub(crate) async fn refresh_access_token(
    client: &reqwest::Client,
    profile: &mut CliProfile,
) -> Result<()> {
    let refresh_token = profile
        .refresh_token
        .clone()
        .ok_or_else(|| anyhow!("refresh token missing; run `ht login` again"))?;
    let url = format!("{}/v2/auth/refresh", profile.server.trim_end_matches('/'));
    let payload = RefreshRequest {
        refresh_token: &refresh_token,
    };
    let response: HttpResponse<TokenPair> = execute_api(
        client.post(url).json(&payload),
        "refresh response decode failed",
    )
    .await?;
    if !response.payload.success {
        return Err(anyhow!(
            "{}",
            api_error_message(&response.payload, "refresh failed")
        ));
    }
    let token_pair = response
        .payload
        .data
        .context("missing token pair in refresh response")?;
    apply_token_pair(profile, token_pair);
    save_profile(profile)?;
    Ok(())
}

pub(crate) async fn ensure_access_token(
    client: &reqwest::Client,
    profile: &mut CliProfile,
) -> Result<()> {
    if profile.api_key_direct {
        return Ok(());
    }
    if !token_expired(profile) {
        return Ok(());
    }
    refresh_access_token(client, profile)
        .await
        .map_err(|error| anyhow!("{error}. please run `ht login --server ... --token ...`"))
}

pub(crate) async fn fetch_snapshot(
    client: &reqwest::Client,
    profile: &mut CliProfile,
    repo: &str,
    branch: &str,
    to_changeset_id: Option<&str>,
) -> Result<SyncResponse> {
    let mut url = format!(
        "{}/v2/sync/{}?branch={}",
        profile.server.trim_end_matches('/'),
        repo,
        branch
    );
    if let Some(to) = to_changeset_id {
        url.push_str("&to_changeset_id=");
        url.push_str(to);
    }

    let response: ApiResponse<SyncResponse> = send_authed_api(
        client,
        profile,
        |client, profile| with_auth(client.get(&url), profile),
        "sync response decode failed",
    )
    .await?;
    if !response.success {
        return Err(anyhow!(api_error_message(&response, "sync failed")));
    }
    response.data.context("missing response data")
}

pub(crate) async fn fetch_owner_id(
    client: &reqwest::Client,
    profile: &CliProfile,
) -> Result<String> {
    let url = format!("{}/v2/auth/verify", profile.server.trim_end_matches('/'));
    let response: HttpResponse<VerifyResponse> = execute_api(
        client.get(url).header("X-API-Key", &profile.api_key),
        "verify response decode failed",
    )
    .await?;
    if !response.payload.success {
        return Err(anyhow!(api_error_message(
            &response.payload,
            "verify failed"
        )));
    }
    let verify = response.payload.data.context("missing verify data")?;
    if !verify.valid {
        return Err(anyhow!("api key is invalid"));
    }
    verify.owner_id.context("missing owner_id from verify")
}

pub(crate) async fn resolve_base_changeset(
    client: &reqwest::Client,
    profile: &mut CliProfile,
    repo: &str,
    branch: &str,
    current: Option<&str>,
) -> Result<String> {
    if let Some(existing) = current {
        return Ok(existing.to_string());
    }

    let url = format!(
        "{}/v2/branches/{}",
        profile.server.trim_end_matches('/'),
        repo
    );
    let response: ApiResponse<BranchListResponse> = send_authed_api(
        client,
        profile,
        |client, profile| with_auth(client.get(&url), profile),
        "resolve base response decode failed",
    )
    .await?;
    if !response.success {
        return Err(anyhow!(
            "{}",
            api_error_message(&response, "failed to resolve branch head")
        ));
    }
    let data = response.data.context("missing response data")?;
    let branch_item = data
        .branches
        .into_iter()
        .find(|item| item.name == branch)
        .ok_or_else(|| anyhow!("branch not found: {branch}"))?;
    Ok(branch_item
        .head_changeset_id
        .unwrap_or_else(|| ROOT_BASE_CHANGESET_ID.to_string()))
}

pub(crate) async fn fetch_blob_bytes(
    client: &reqwest::Client,
    profile: &mut CliProfile,
    blob_hash: &str,
) -> Result<Vec<u8>> {
    let cache_path = cache_object_path(blob_hash)?;
    if cache_path.exists() {
        let bytes = fs::read(&cache_path)
            .with_context(|| format!("failed to read cached object {}", cache_path.display()))?;
        let actual = StorageHash::hash_bytes(&bytes);
        if actual != blob_hash {
            return Err(anyhow!(
                "cached object hash mismatch for {}: got {}",
                blob_hash,
                actual
            ));
        }
        return Ok(bytes);
    }

    ensure_access_token(client, profile).await?;
    let url = format!(
        "{}/v2/storage/download/{}",
        profile.server.trim_end_matches('/'),
        blob_hash
    );
    let response = with_auth(client.get(url), profile).send().await?;
    if !response.status().is_success() {
        return Err(anyhow!(
            "download failed for {}: HTTP {}",
            blob_hash,
            response.status()
        ));
    }
    let bytes = response.bytes().await?.to_vec();
    let actual = StorageHash::hash_bytes(&bytes);
    if actual != blob_hash {
        return Err(anyhow!(
            "downloaded object hash mismatch for {}: got {}",
            blob_hash,
            actual
        ));
    }
    cache_blob(blob_hash, &bytes)?;
    Ok(bytes)
}

pub(crate) async fn fetch_locks(
    client: &reqwest::Client,
    profile: &mut CliProfile,
    repo_id: &str,
) -> Result<Vec<FileLockInfo>> {
    let url = format!("{}/v2/locks", profile.server.trim_end_matches('/'));
    let response: ApiResponse<Vec<FileLockInfo>> = send_authed_api(
        client,
        profile,
        |client, profile| {
            with_auth(
                client
                    .get(&url)
                    .query(&[("repo_id", repo_id), ("scope", "asset")]),
                profile,
            )
        },
        "locks response decode failed",
    )
    .await?;
    if !response.success {
        return Err(anyhow!(api_error_message(&response, "list locks failed")));
    }
    Ok(response.data.unwrap_or_default())
}

pub(crate) async fn upload_blob_from_bytes(
    client: &reqwest::Client,
    profile: &mut CliProfile,
    file_path: &Path,
    bytes: &[u8],
    chunk_size: usize,
    chunk_size_policy: &str,
    manifest_only: bool,
) -> Result<ComposeBlobResponse> {
    if bytes.len() <= DIRECT_UPLOAD_THRESHOLD_BYTES {
        let blob = upload_blob_direct(client, profile, file_path, bytes).await?;
        return Ok(blob);
    }
    upload_blob_via_chunks(
        client,
        profile,
        file_path,
        bytes,
        chunk_size,
        chunk_size_policy,
        manifest_only,
    )
    .await
}

pub(crate) async fn upload_blob_direct(
    client: &reqwest::Client,
    profile: &mut CliProfile,
    file_path: &Path,
    bytes: &[u8],
) -> Result<ComposeBlobResponse> {
    ensure_access_token(client, profile).await?;
    let part = multipart::Part::bytes(bytes.to_vec())
        .file_name(
            file_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("asset.bin")
                .to_string(),
        )
        .mime_str("application/octet-stream")?;
    let form = multipart::Form::new().part("file", part);
    let url = format!("{}/v2/storage/upload", profile.server.trim_end_matches('/'));
    let response: HttpResponse<UploadResponse> = execute_api(
        with_auth(client.post(url).multipart(form), profile),
        "upload response decode failed",
    )
    .await?;
    if !response.payload.success {
        return Err(anyhow!(api_error_message(
            &response.payload,
            "upload failed"
        )));
    }
    let uploaded = response
        .payload
        .data
        .context("missing upload response data")?;
    Ok(ComposeBlobResponse {
        blob_hash: uploaded.hash,
        size_bytes: uploaded.size_bytes,
    })
}

pub(crate) async fn upload_blob_via_chunks(
    client: &reqwest::Client,
    profile: &mut CliProfile,
    file_path: &Path,
    bytes: &[u8],
    chunk_size: usize,
    chunk_size_policy: &str,
    manifest_only: bool,
) -> Result<ComposeBlobResponse> {
    let file_name = file_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("asset.bin")
        .to_string();
    let chunk_size = chunk_size.max(64 * 1024);
    let mut chunks = Vec::new();
    let mut cursor = 0usize;
    let mut index = 0usize;
    while cursor < bytes.len() {
        let end = (cursor + chunk_size).min(bytes.len());
        chunks.push(ManifestChunk {
            i: index,
            chunk_hash: StorageHash::hash_bytes(&bytes[cursor..end]),
            size: end - cursor,
        });
        cursor = end;
        index += 1;
    }

    let hash_list = chunks
        .iter()
        .map(|chunk| chunk.chunk_hash.clone())
        .collect::<Vec<_>>();
    let missing_url = format!("{}/v2/blobs/missing", profile.server.trim_end_matches('/'));
    let missing_resp: ApiResponse<MissingChunksResponse> = send_authed_api(
        client,
        profile,
        |client, profile| {
            with_auth(
                client.post(&missing_url).json(&MissingChunksRequest {
                    chunk_hashes: &hash_list,
                }),
                profile,
            )
        },
        "missing-chunk response decode failed",
    )
    .await?;
    if !missing_resp.success {
        return Err(anyhow!(api_error_message(
            &missing_resp,
            "query missing chunks failed"
        )));
    }
    let missing = missing_resp
        .data
        .context("missing missing-chunk response data")?
        .missing
        .into_iter()
        .collect::<HashSet<_>>();

    cursor = 0usize;
    for chunk in &chunks {
        let end = (cursor + chunk.size).min(bytes.len());
        if missing.contains(&chunk.chunk_hash) {
            let upload_url = format!(
                "{}/v2/blobs/chunks/{}",
                profile.server.trim_end_matches('/'),
                chunk.chunk_hash
            );
            let payload = bytes[cursor..end].to_vec();
            let upload_resp: ApiResponse<serde_json::Value> = send_authed_api(
                client,
                profile,
                move |client, profile| {
                    with_auth(client.put(&upload_url).body(payload.clone()), profile)
                },
                "chunk upload response decode failed",
            )
            .await?;
            if !upload_resp.success {
                return Err(anyhow!(api_error_message(
                    &upload_resp,
                    "chunk upload failed"
                )));
            }
        }
        cursor = end;
    }

    let manifest_url = format!("{}/v2/manifests", profile.server.trim_end_matches('/'));
    let manifest_req = CreateManifestRequest {
        version: 1,
        chunk_size_policy,
        chunks: &chunks,
        file_meta: serde_json::json!({
            "path": file_path.to_string_lossy(),
            "name": file_name,
            "size": bytes.len(),
        }),
    };
    let manifest_resp: ApiResponse<CreateManifestResponse> = send_authed_api(
        client,
        profile,
        |client, profile| with_auth(client.post(&manifest_url).json(&manifest_req), profile),
        "manifest response decode failed",
    )
    .await?;
    if !manifest_resp.success {
        return Err(anyhow!(api_error_message(
            &manifest_resp,
            "manifest create failed"
        )));
    }
    let manifest = manifest_resp
        .data
        .context("missing manifest response data")?;

    if manifest_only {
        return Ok(ComposeBlobResponse {
            blob_hash: manifest.manifest_hash,
            size_bytes: bytes.len() as u64,
        });
    }

    let compose_url = format!("{}/v2/blobs/compose", profile.server.trim_end_matches('/'));
    let compose_resp: ApiResponse<ComposeBlobResponse> = send_authed_api(
        client,
        profile,
        |client, profile| {
            with_auth(
                client.post(&compose_url).json(&ComposeBlobRequest {
                    manifest_hash: &manifest.manifest_hash,
                }),
                profile,
            )
        },
        "compose response decode failed",
    )
    .await?;
    if !compose_resp.success {
        return Err(anyhow!(api_error_message(
            &compose_resp,
            "compose blob failed"
        )));
    }
    compose_resp.data.context("missing compose response data")
}

// ── High-risk helpers ──

pub(crate) fn build_high_risk_headers(
    explicit_secret: Option<&str>,
    action: &str,
    actor_id: &str,
    payload: &serde_json::Value,
) -> Option<HighRiskHeaders> {
    let secret = explicit_secret
        .map(str::to_string)
        .or_else(|| env::var("HT_HIGH_RISK_SIGNING_SECRET").ok())?;
    let nonce = next_nonce();
    let timestamp = now_unix();
    let signature = high_risk_signature(&secret, action, actor_id, &nonce, timestamp, payload);
    Some(HighRiskHeaders {
        nonce,
        timestamp,
        signature,
    })
}

pub(crate) fn apply_high_risk_headers(
    request: RequestBuilder,
    headers: Option<&HighRiskHeaders>,
) -> RequestBuilder {
    let Some(headers) = headers else {
        return request;
    };
    request
        .header("X-HT-Nonce", &headers.nonce)
        .header("X-HT-Timestamp", headers.timestamp.to_string())
        .header("X-HT-Signature", &headers.signature)
}

pub(crate) fn high_risk_signature(
    secret: &str,
    action: &str,
    actor_id: &str,
    nonce: &str,
    timestamp: i64,
    payload: &serde_json::Value,
) -> String {
    let payload_hash = blake3::hash(
        serde_json::to_string(payload)
            .unwrap_or_default()
            .as_bytes(),
    )
    .to_hex()
    .to_string();
    let material = format!("{secret}|{action}|{actor_id}|{nonce}|{timestamp}|{payload_hash}");
    blake3::hash(material.as_bytes()).to_hex().to_string()
}

pub(crate) fn next_nonce() -> String {
    let counter = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}-{}-{counter}", now_unix(), std::process::id())
}

// ── Session / checkpoint helpers ──

pub(crate) async fn ensure_session(
    client: &reqwest::Client,
    profile: &mut CliProfile,
    repo: &str,
    branch: &str,
    requested_session: Option<&str>,
    message: Option<&str>,
) -> Result<String> {
    if let Some(session_id) = requested_session {
        return Ok(session_id.to_string());
    }
    if let Ok(session) = load_session_state() {
        if let Some(session_id) = session.current_session_id {
            return Ok(session_id);
        }
    }

    let workspace_root = std::env::current_dir()?.to_string_lossy().to_string();
    let base_changeset_id = load_workspace()
        .ok()
        .and_then(|workspace| workspace.base_changeset_id)
        .or_else(|| load_stage().ok().and_then(|stage| stage.base_changeset_id));
    let payload = CreateSessionRequest {
        repo_id: repo,
        branch,
        base_changeset_id: base_changeset_id.as_deref(),
        workspace_root: &workspace_root,
        trigger_reason: "agent_session",
        semantic_summary: message,
    };
    let url = format!("{}/v2/sessions", profile.server.trim_end_matches('/'));
    let response: ApiResponse<AgentSessionRecord> = send_authed_api(
        client,
        profile,
        |client, profile| with_auth(client.post(&url).json(&payload), profile),
        "create session response decode failed",
    )
    .await?;
    if !response.success {
        return Err(anyhow!(api_error_message(
            &response,
            "create session failed"
        )));
    }
    let session = response.data.context("missing session response data")?;
    save_session_state(&SessionState {
        current_session_id: Some(session.session_id.clone()),
    })?;
    Ok(session.session_id)
}

pub(crate) async fn create_remote_checkpoint(
    client: &reqwest::Client,
    profile: &mut CliProfile,
    session_id: &str,
    trigger_reason: &str,
    message: Option<&str>,
    assets: &[CheckpointAsset],
    save_endpoint: bool,
) -> Result<SessionCheckpointRecord> {
    let payload = CreateCheckpointRequest {
        trigger_reason,
        semantic_summary: message,
        assets,
    };
    let suffix = if save_endpoint {
        "save".to_string()
    } else {
        "checkpoints".to_string()
    };
    let url = format!(
        "{}/v2/sessions/{}/{}",
        profile.server.trim_end_matches('/'),
        session_id,
        suffix
    );
    let response: ApiResponse<SessionCheckpointRecord> = send_authed_api(
        client,
        profile,
        |client, profile| with_auth(client.post(&url).json(&payload), profile),
        "checkpoint response decode failed",
    )
    .await?;
    if !response.success {
        return Err(anyhow!(api_error_message(
            &response,
            "checkpoint create failed"
        )));
    }
    response.data.context("missing checkpoint response data")
}

pub(crate) async fn fetch_checkpoint_snapshot(
    client: &reqwest::Client,
    profile: &mut CliProfile,
    checkpoint_id: &str,
) -> Result<CheckpointSnapshot> {
    let url = format!(
        "{}/v2/checkpoints/{}/snapshot",
        profile.server.trim_end_matches('/'),
        checkpoint_id
    );
    let response: ApiResponse<CheckpointSnapshot> = send_authed_api(
        client,
        profile,
        |client, profile| with_auth(client.get(&url), profile),
        "checkpoint snapshot response decode failed",
    )
    .await?;
    if !response.success {
        return Err(anyhow!(api_error_message(
            &response,
            "checkpoint snapshot failed"
        )));
    }
    response.data.context("missing checkpoint snapshot data")
}

pub(crate) async fn collect_checkpoint_assets(
    client: &reqwest::Client,
    profile: &mut CliProfile,
    branch: &str,
) -> Result<Vec<CheckpointAsset>> {
    let stage = load_stage().unwrap_or_else(|_| StageFile::default_for_branch(branch));
    if !stage.assets.is_empty() {
        return Ok(stage
            .assets
            .into_iter()
            .filter_map(|asset| {
                asset.blob_hash.map(|blob_hash| CheckpointAsset {
                    asset_id: asset.asset_id.unwrap_or_else(|| asset.path.clone()),
                    path: asset.path,
                    blob_hash,
                })
            })
            .collect());
    }
    let workspace = load_workspace()?;
    let mut assets = collect_workspace_checkpoint_assets(&workspace)?;
    let workspace_root = PathBuf::from(&workspace.workspace_root);
    for asset in &mut assets {
        let target = resolve_workspace_target(&workspace_root, &asset.path)?;
        let bytes =
            fs::read(&target).with_context(|| format!("failed to read {}", target.display()))?;
        let uploaded = upload_blob_from_bytes(
            client,
            profile,
            &target,
            &bytes,
            4 * 1024 * 1024,
            "fixed-4m",
            false,
        )
        .await?;
        asset.blob_hash = uploaded.blob_hash;
    }
    Ok(assets)
}

pub(crate) async fn materialize_checkpoint_snapshot(
    client: &reqwest::Client,
    profile: &mut CliProfile,
    snapshot: &CheckpointSnapshot,
) -> Result<()> {
    let workspace_root = std::env::current_dir()?;
    let mut checked_out_assets = Vec::with_capacity(snapshot.assets.len());
    for asset in &snapshot.assets {
        let target = resolve_workspace_target(&workspace_root, &asset.path)?;
        let bytes = fetch_blob_bytes(client, profile, &asset.blob_hash).await?;
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&target, &bytes)
            .with_context(|| format!("failed to write {}", target.display()))?;
        checked_out_assets.push(WorkspaceFile {
            path: asset.path.clone(),
            blob_hash: asset.blob_hash.clone(),
            asset_id: Some(asset.asset_id.clone()),
        });
    }
    save_workspace(&WorkspaceState {
        repo_id: snapshot.repo_id.clone(),
        branch: snapshot.branch.clone(),
        workspace_root: workspace_root.to_string_lossy().to_string(),
        base_changeset_id: snapshot.base_changeset_id.clone(),
        checked_out_assets,
        last_synced_at: now_unix(),
    })?;
    let mut stage = StageFile::default_for_branch(&snapshot.branch);
    stage.base_changeset_id = snapshot.base_changeset_id.clone();
    save_stage(&stage)?;
    Ok(())
}

// ── Lock helper ──

pub(crate) async fn send_lock_path_request(
    action: &str,
    endpoint: &str,
    path: &str,
    repo_id: Option<&str>,
) -> Result<FileLockInfo> {
    let mut profile = load_profile()?;
    let client = reqwest::Client::new();
    let repo_id = match repo_id {
        Some(repo_id) => repo_id.to_string(),
        None => resolve_repo(&profile, None)?,
    };
    let payload = LockRequest {
        file_path: path,
        repo_id: &repo_id,
        scope: "asset",
    };
    let url = format!(
        "{}/v2/locks/{}",
        profile.server.trim_end_matches('/'),
        endpoint
    );
    let response: ApiResponse<FileLockInfo> = send_authed_api(
        &client,
        &mut profile,
        |client, profile| with_auth(client.post(&url).json(&payload), profile),
        &format!("{action} response decode failed"),
    )
    .await?;
    if !response.success {
        return Err(anyhow!(api_error_message(
            &response,
            &format!("{action} failed")
        )));
    }
    response.data.context("missing response data")
}

// ── Add file helper ──

pub(crate) async fn add_file(
    file_path: &Path,
    asset_path: Option<&str>,
    branch: &str,
) -> Result<()> {
    let mut profile = load_profile()?;
    let client = reqwest::Client::new();
    let repo_path = asset_path
        .map(|path| path.to_string())
        .unwrap_or_else(|| normalize_asset_path(file_path));
    let bytes = fs::read(file_path)
        .with_context(|| format!("failed to read file {}", file_path.display()))?;
    if bytes.is_empty() {
        return Err(anyhow!("file is empty"));
    }

    let blob_hash = upload_blob_from_bytes(
        &client,
        &mut profile,
        file_path,
        &bytes,
        4 * 1024 * 1024,
        "fixed-4m",
        false,
    )
    .await?
    .blob_hash;

    cache_blob(&blob_hash, &bytes)?;

    let mut stage = load_stage().unwrap_or_else(|_| StageFile::default_for_branch(branch));
    if stage.branch != branch {
        stage = StageFile::default_for_branch(branch);
    }
    let asset_id = load_workspace().ok().and_then(|workspace| {
        (workspace.branch == branch)
            .then_some(workspace.checked_out_assets)
            .into_iter()
            .flatten()
            .find(|asset| asset.path == repo_path)
            .and_then(|asset| asset.asset_id)
    });
    upsert_stage_asset(&mut stage, &repo_path, Some(blob_hash.clone()), asset_id);
    save_stage(&stage)?;
    println!(
        "staged file {} as {} on {} (blob={})",
        file_path.display(),
        repo_path,
        branch,
        blob_hash
    );
    Ok(())
}
