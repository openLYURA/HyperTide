use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use crate::core::error::HyperTideError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

pub mod repo_pg;
use self::repo_pg::VersionRepoPg;

pub const ROOT_BASE_CHANGESET_ID: &str = "ROOT";

#[cfg(windows)]
fn replace_state_file(temp_path: &Path, state_path: &Path) -> std::io::Result<()> {
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;

    if !state_path.exists() {
        return std::fs::rename(temp_path, state_path);
    }

    let state_wide = state_path
        .as_os_str()
        .encode_wide()
        .chain(once(0))
        .collect::<Vec<_>>();
    let temp_wide = temp_path
        .as_os_str()
        .encode_wide()
        .chain(once(0))
        .collect::<Vec<_>>();
    let replaced = unsafe {
        ReplaceFileW(
            state_wide.as_ptr(),
            temp_wide.as_ptr(),
            std::ptr::null(),
            0,
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if replaced == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn replace_state_file(temp_path: &Path, state_path: &Path) -> std::io::Result<()> {
    std::fs::rename(temp_path, state_path)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangesetKind {
    Normal,
    Rollback,
}

impl ChangesetKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChangesetKind::Normal => "normal",
            ChangesetKind::Rollback => "rollback",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangesetVisibility {
    Visible,
    Draft,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangesetStatus {
    Draft,
    Approved,
    Visible,
}

impl ChangesetStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChangesetStatus::Draft => "draft",
            ChangesetStatus::Approved => "approved",
            ChangesetStatus::Visible => "visible",
        }
    }
}

fn default_changeset_status() -> ChangesetStatus {
    ChangesetStatus::Visible
}

fn staging_ref(repo_id: &str, branch: &str, changeset_id: &str) -> String {
    format!("refs/ht/staging/{repo_id}/{branch}/{changeset_id}")
}

fn visible_ref(branch: &str) -> String {
    format!("refs/heads/{branch}")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetDelta {
    #[serde(default)]
    pub asset_id: Option<String>,
    pub path: String,
    #[serde(default)]
    pub from_blob_hash: Option<String>,
    pub blob_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangesetRecord {
    pub changeset_id: String,
    pub repo_id: String,
    pub branch: String,
    pub parent_changeset_id: Option<String>,
    pub base_changeset_id: Option<String>,
    pub kind: ChangesetKind,
    pub rollback_of: Option<String>,
    pub author: String,
    pub message: String,
    pub created_at: DateTime<Utc>,
    #[serde(default = "default_changeset_status")]
    pub status: ChangesetStatus,
    pub approved_by: Option<String>,
    pub approved_at: Option<DateTime<Utc>>,
    pub promoted_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub staging_ref: Option<String>,
    #[serde(default)]
    pub visible_ref: Option<String>,
    #[serde(default)]
    pub intent_id: Option<String>,
    #[serde(default)]
    pub task_id: Option<String>,
    #[serde(default)]
    pub agent_run_id: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub parent_checkpoint_id: Option<String>,
    #[serde(default)]
    pub risk_level: Option<String>,
    #[serde(default)]
    pub semantic_summary: Option<String>,
    pub assets: Vec<AssetDelta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchRecord {
    pub name: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub is_default: bool,
    pub head_changeset_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SubmitChangesetInput {
    pub repo_id: String,
    pub branch: String,
    pub base_changeset_id: Option<String>,
    pub kind: ChangesetKind,
    pub rollback_of: Option<String>,
    pub author: String,
    pub message: String,
    pub visibility: ChangesetVisibility,
    pub intent_id: Option<String>,
    pub task_id: Option<String>,
    pub agent_run_id: Option<String>,
    pub session_id: Option<String>,
    pub parent_checkpoint_id: Option<String>,
    pub risk_level: Option<String>,
    pub semantic_summary: Option<String>,
    pub assets: Vec<AssetDelta>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HistoryPage {
    pub items: Vec<ChangesetRecord>,
    pub next_cursor: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChangesetGate {
    pub repo_id: String,
    pub changeset_id: String,
    pub branch: String,
    pub status: ChangesetStatus,
    pub required_state: &'static str,
    pub can_promote: bool,
    pub blocking_reason: Option<String>,
    pub base_changeset_id: Option<String>,
    pub branch_head_changeset_id: Option<String>,
    pub staging_ref: Option<String>,
    pub visible_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncSnapshot {
    pub repo_id: String,
    pub branch: String,
    pub changeset_id: Option<String>,
    pub assets: Vec<SnapshotEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RepoSummary {
    pub repo_id: String,
    pub default_branch: String,
    pub branch_count: usize,
    pub default_head_changeset_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RepoInfo {
    pub repo_id: String,
    pub default_branch: String,
    pub branch_count: usize,
    pub default_head_changeset_id: Option<String>,
    pub branches: Vec<BranchRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotEntry {
    pub asset_id: String,
    pub path: String,
    pub blob_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct SnapshotAsset {
    pub asset_id: String,
    pub path: String,
    pub blob_hash: String,
}

#[derive(Debug, Clone)]
pub struct RollbackPlan {
    pub repo_id: String,
    pub branch: String,
    pub base_changeset_id: String,
    pub target_changeset_id: String,
    pub assets: Vec<AssetDelta>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersioningError {
    RepoAlreadyExists {
        repo_id: String,
    },
    RepoNotFound {
        repo_id: String,
    },
    BranchNotFound {
        repo_id: String,
        branch: String,
    },
    BranchAlreadyExists {
        repo_id: String,
        branch: String,
    },
    ChangesetNotFound {
        repo_id: String,
        changeset_id: String,
    },
    BaseChangesetRequired,
    BaseChangesetMismatch {
        repo_id: String,
        branch: String,
        expected: Option<String>,
        got: Option<String>,
    },
    InvalidRollbackTarget {
        repo_id: String,
        branch: String,
        target_changeset_id: String,
    },
    InvalidChangesetState {
        repo_id: String,
        changeset_id: String,
        status: ChangesetStatus,
        expected: &'static str,
    },
    InvalidAssetLayout {
        repo_id: String,
        message: String,
    },
    Persistence {
        message: String,
    },
}

#[derive(Clone)]
pub struct VersionManager {
    repos: Arc<RwLock<HashMap<String, RepoState>>>,
    persistence_path: Option<PathBuf>,
    repo_pg: Option<VersionRepoPg>,
    mutation_lock: Arc<tokio::sync::Mutex<()>>,
}

impl VersionManager {
    pub fn new() -> Self {
        Self {
            repos: Arc::new(RwLock::new(HashMap::new())),
            persistence_path: None,
            repo_pg: None,
            mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    pub fn with_persistence(path: impl AsRef<Path>) -> Self {
        let persistence_path = path.as_ref().to_path_buf();
        let repos = match Self::load_repos(&persistence_path) {
            Ok(repos) => repos,
            Err(error) => {
                tracing::warn!(
                    "versioning persistence load failed at {}: {}",
                    persistence_path.display(),
                    error
                );
                HashMap::new()
            }
        };

        Self {
            repos: Arc::new(RwLock::new(repos)),
            persistence_path: Some(persistence_path),
            repo_pg: None,
            mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    pub async fn with_pg(pool: PgPool) -> Result<Self, HyperTideError> {
        let repo_pg = VersionRepoPg::new(pool);
        let repos = repo_pg.load_repos().await.map_err(|error| {
            HyperTideError::Persistence(format!("failed to load versioning state from db: {error}"))
        })?;
        Ok(Self {
            repos: Arc::new(RwLock::new(repos)),
            persistence_path: None,
            repo_pg: Some(repo_pg),
            mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    pub async fn create_repo(
        &self,
        repo_id: &str,
        default_branch: &str,
        created_by: &str,
    ) -> Result<RepoInfo, VersioningError> {
        let _mutation = self.mutation_lock.lock().await;
        let (info, snapshot) = {
            let mut snapshot = self.repos.read().expect("versioning lock poisoned").clone();
            if snapshot.contains_key(repo_id) {
                return Err(VersioningError::RepoAlreadyExists {
                    repo_id: repo_id.to_string(),
                });
            }

            let repo = RepoState::new_with_default(default_branch, created_by);
            snapshot.insert(repo_id.to_string(), repo);
            let info =
                Self::repo_info_from_state(repo_id, snapshot.get(repo_id).expect("repo exists"));
            (info, snapshot)
        };
        self.persist_repo(repo_id, &snapshot)
            .await
            .map_err(|message| VersioningError::Persistence { message })?;
        *self.repos.write().expect("versioning lock poisoned") = snapshot;
        Ok(info)
    }

    pub fn list_repos(&self) -> Vec<RepoSummary> {
        let repos = self.repos.read().expect("versioning lock poisoned");
        let mut items: Vec<RepoSummary> = repos
            .iter()
            .map(|(repo_id, repo)| Self::repo_summary_from_state(repo_id, repo))
            .collect();
        items.sort_by(|a, b| a.repo_id.cmp(&b.repo_id));
        items
    }

    pub fn get_repo_info(&self, repo_id: &str) -> Result<RepoInfo, VersioningError> {
        let repos = self.repos.read().expect("versioning lock poisoned");
        let repo = repos
            .get(repo_id)
            .ok_or_else(|| VersioningError::RepoNotFound {
                repo_id: repo_id.to_string(),
            })?;
        Ok(Self::repo_info_from_state(repo_id, repo))
    }

    pub async fn create_branch(
        &self,
        repo_id: &str,
        branch: &str,
        from_changeset_id: Option<&str>,
        created_by: &str,
    ) -> Result<BranchRecord, VersioningError> {
        let _mutation = self.mutation_lock.lock().await;
        let (record, snapshot) = {
            let mut snapshot = self.repos.read().expect("versioning lock poisoned").clone();
            let repo = snapshot
                .entry(repo_id.to_string())
                .or_insert_with(|| RepoState::new(created_by));
            repo.ensure_default_branch(created_by);

            if repo.branches.contains_key(branch) {
                return Err(VersioningError::BranchAlreadyExists {
                    repo_id: repo_id.to_string(),
                    branch: branch.to_string(),
                });
            }

            let head = if let Some(id) = from_changeset_id {
                if !repo.changesets.contains_key(id) {
                    return Err(VersioningError::ChangesetNotFound {
                        repo_id: repo_id.to_string(),
                        changeset_id: id.to_string(),
                    });
                }
                Some(id.to_string())
            } else {
                repo.default_head()
            };

            let history = if let Some(ref head_id) = head {
                repo.lineage_to(head_id)
                    .ok_or_else(|| VersioningError::ChangesetNotFound {
                        repo_id: repo_id.to_string(),
                        changeset_id: head_id.clone(),
                    })?
            } else {
                Vec::new()
            };

            let record = BranchRecord {
                name: branch.to_string(),
                created_by: created_by.to_string(),
                created_at: Utc::now(),
                is_default: false,
                head_changeset_id: head.clone(),
            };

            repo.branches.insert(
                branch.to_string(),
                BranchState {
                    record: record.clone(),
                    history,
                },
            );

            (record, snapshot)
        };
        self.persist_repo(repo_id, &snapshot)
            .await
            .map_err(|message| VersioningError::Persistence { message })?;
        *self.repos.write().expect("versioning lock poisoned") = snapshot;
        Ok(record)
    }

    fn repo_summary_from_state(repo_id: &str, repo: &RepoState) -> RepoSummary {
        RepoSummary {
            repo_id: repo_id.to_string(),
            default_branch: repo.default_branch.clone(),
            branch_count: repo.branches.len(),
            default_head_changeset_id: repo.default_head(),
        }
    }

    fn repo_info_from_state(repo_id: &str, repo: &RepoState) -> RepoInfo {
        let mut branches: Vec<BranchRecord> =
            repo.branches.values().map(|b| b.record.clone()).collect();
        branches.sort_by(|a, b| a.name.cmp(&b.name));
        RepoInfo {
            repo_id: repo_id.to_string(),
            default_branch: repo.default_branch.clone(),
            branch_count: branches.len(),
            default_head_changeset_id: repo.default_head(),
            branches,
        }
    }

    pub fn list_branches(&self, repo_id: &str) -> Result<Vec<BranchRecord>, VersioningError> {
        let repos = self.repos.read().expect("versioning lock poisoned");
        let repo = repos
            .get(repo_id)
            .ok_or_else(|| VersioningError::RepoNotFound {
                repo_id: repo_id.to_string(),
            })?;

        let mut items: Vec<BranchRecord> =
            repo.branches.values().map(|b| b.record.clone()).collect();
        items.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(items)
    }

    pub async fn submit_changeset(
        &self,
        input: SubmitChangesetInput,
    ) -> Result<ChangesetRecord, VersioningError> {
        let _mutation = self.mutation_lock.lock().await;
        let repo_id = input.repo_id.clone();
        let (record, snapshot) = {
            let mut snapshot = self.repos.read().expect("versioning lock poisoned").clone();
            let repo = snapshot
                .entry(input.repo_id.clone())
                .or_insert_with(|| RepoState::new(&input.author));
            repo.ensure_default_branch(&input.author);
            let record = Self::submit_internal(repo, input)?;
            (record, snapshot)
        };
        self.persist_repo(&repo_id, &snapshot)
            .await
            .map_err(|message| VersioningError::Persistence { message })?;
        *self.repos.write().expect("versioning lock poisoned") = snapshot;
        Ok(record)
    }

    pub async fn approve_changeset(
        &self,
        repo_id: &str,
        changeset_id: &str,
        approver: &str,
    ) -> Result<ChangesetRecord, VersioningError> {
        let _mutation = self.mutation_lock.lock().await;
        let (record, snapshot) = {
            let mut snapshot = self.repos.read().expect("versioning lock poisoned").clone();
            let repo = snapshot
                .get_mut(repo_id)
                .ok_or_else(|| VersioningError::RepoNotFound {
                    repo_id: repo_id.to_string(),
                })?;
            let record = repo.changesets.get_mut(changeset_id).ok_or_else(|| {
                VersioningError::ChangesetNotFound {
                    repo_id: repo_id.to_string(),
                    changeset_id: changeset_id.to_string(),
                }
            })?;

            match record.status {
                ChangesetStatus::Draft => {
                    record.status = ChangesetStatus::Approved;
                    record.approved_by = Some(approver.to_string());
                    record.approved_at = Some(Utc::now());
                }
                status => {
                    return Err(VersioningError::InvalidChangesetState {
                        repo_id: repo_id.to_string(),
                        changeset_id: changeset_id.to_string(),
                        status,
                        expected: "draft",
                    });
                }
            }

            (record.clone(), snapshot)
        };
        self.persist_repo(repo_id, &snapshot)
            .await
            .map_err(|message| VersioningError::Persistence { message })?;
        *self.repos.write().expect("versioning lock poisoned") = snapshot;
        Ok(record)
    }

    pub async fn promote_changeset(
        &self,
        repo_id: &str,
        changeset_id: &str,
        promoter: &str,
    ) -> Result<ChangesetRecord, VersioningError> {
        let _mutation = self.mutation_lock.lock().await;
        let (record, snapshot) = {
            let mut snapshot = self.repos.read().expect("versioning lock poisoned").clone();
            let repo = snapshot
                .get_mut(repo_id)
                .ok_or_else(|| VersioningError::RepoNotFound {
                    repo_id: repo_id.to_string(),
                })?;

            let record_view = repo.changesets.get(changeset_id).ok_or_else(|| {
                VersioningError::ChangesetNotFound {
                    repo_id: repo_id.to_string(),
                    changeset_id: changeset_id.to_string(),
                }
            })?;
            if record_view.status != ChangesetStatus::Approved {
                return Err(VersioningError::InvalidChangesetState {
                    repo_id: repo_id.to_string(),
                    changeset_id: changeset_id.to_string(),
                    status: record_view.status,
                    expected: "approved",
                });
            }

            let branch = record_view.branch.clone();
            let base = record_view.base_changeset_id.clone();
            let branch_state =
                repo.branches
                    .get_mut(&branch)
                    .ok_or_else(|| VersioningError::BranchNotFound {
                        repo_id: repo_id.to_string(),
                        branch: branch.clone(),
                    })?;
            let expected_head = branch_state.record.head_changeset_id.clone();
            if expected_head != base {
                return Err(VersioningError::BaseChangesetMismatch {
                    repo_id: repo_id.to_string(),
                    branch,
                    expected: expected_head,
                    got: base,
                });
            }

            branch_state.record.head_changeset_id = Some(changeset_id.to_string());
            if !branch_state.history.iter().any(|id| id == changeset_id) {
                branch_state.history.push(changeset_id.to_string());
            }

            let record = repo.changesets.get_mut(changeset_id).ok_or_else(|| {
                VersioningError::ChangesetNotFound {
                    repo_id: repo_id.to_string(),
                    changeset_id: changeset_id.to_string(),
                }
            })?;
            record.status = ChangesetStatus::Visible;
            if record.approved_by.is_none() {
                record.approved_by = Some(promoter.to_string());
                record.approved_at = Some(Utc::now());
            }
            record.promoted_at = Some(Utc::now());
            record.visible_ref = Some(visible_ref(&record.branch));

            (record.clone(), snapshot)
        };
        self.persist_repo(repo_id, &snapshot)
            .await
            .map_err(|message| VersioningError::Persistence { message })?;
        *self.repos.write().expect("versioning lock poisoned") = snapshot;
        Ok(record)
    }

    pub fn changeset_gate(
        &self,
        repo_id: &str,
        changeset_id: &str,
    ) -> Result<ChangesetGate, VersioningError> {
        let repos = self.repos.read().expect("versioning lock poisoned");
        let repo = repos
            .get(repo_id)
            .ok_or_else(|| VersioningError::RepoNotFound {
                repo_id: repo_id.to_string(),
            })?;
        let record = repo.changesets.get(changeset_id).ok_or_else(|| {
            VersioningError::ChangesetNotFound {
                repo_id: repo_id.to_string(),
                changeset_id: changeset_id.to_string(),
            }
        })?;
        let branch_state =
            repo.branches
                .get(&record.branch)
                .ok_or_else(|| VersioningError::BranchNotFound {
                    repo_id: repo_id.to_string(),
                    branch: record.branch.clone(),
                })?;
        let current_head = branch_state.record.head_changeset_id.clone();
        let base = record.base_changeset_id.clone();

        let (can_promote, blocking_reason) = if record.status != ChangesetStatus::Approved {
            (
                false,
                Some(format!(
                    "changeset status is {}, expected approved",
                    record.status.as_str()
                )),
            )
        } else if current_head != base {
            (
                false,
                Some(format!(
                    "branch head mismatch: current={current_head:?}, base={base:?}"
                )),
            )
        } else {
            (true, None)
        };

        Ok(ChangesetGate {
            repo_id: repo_id.to_string(),
            changeset_id: changeset_id.to_string(),
            branch: record.branch.clone(),
            status: record.status,
            required_state: "approved",
            can_promote,
            blocking_reason,
            base_changeset_id: base,
            branch_head_changeset_id: current_head,
            staging_ref: record.staging_ref.clone(),
            visible_ref: record.visible_ref.clone(),
        })
    }

    pub fn history(
        &self,
        repo_id: &str,
        branch: &str,
        limit: usize,
        cursor: usize,
    ) -> Result<HistoryPage, VersioningError> {
        let repos = self.repos.read().expect("versioning lock poisoned");
        let repo = repos
            .get(repo_id)
            .ok_or_else(|| VersioningError::RepoNotFound {
                repo_id: repo_id.to_string(),
            })?;
        let branch_state =
            repo.branches
                .get(branch)
                .ok_or_else(|| VersioningError::BranchNotFound {
                    repo_id: repo_id.to_string(),
                    branch: branch.to_string(),
                })?;

        let total = branch_state.history.len();
        let max_limit = limit.clamp(1, 200);
        let items: Vec<ChangesetRecord> = branch_state
            .history
            .iter()
            .rev()
            .skip(cursor)
            .take(max_limit)
            .filter_map(|id| repo.changesets.get(id).cloned())
            .collect();

        let consumed = cursor + items.len();
        let next_cursor = if consumed < total {
            Some(consumed)
        } else {
            None
        };
        Ok(HistoryPage { items, next_cursor })
    }

    pub fn build_rollback_plan(
        &self,
        repo_id: &str,
        branch: &str,
        target_changeset_id: &str,
    ) -> Result<RollbackPlan, VersioningError> {
        let repos = self.repos.read().expect("versioning lock poisoned");
        let repo = repos
            .get(repo_id)
            .ok_or_else(|| VersioningError::RepoNotFound {
                repo_id: repo_id.to_string(),
            })?;
        let branch_state =
            repo.branches
                .get(branch)
                .ok_or_else(|| VersioningError::BranchNotFound {
                    repo_id: repo_id.to_string(),
                    branch: branch.to_string(),
                })?;

        let head_id = branch_state
            .record
            .head_changeset_id
            .clone()
            .ok_or_else(|| VersioningError::InvalidRollbackTarget {
                repo_id: repo_id.to_string(),
                branch: branch.to_string(),
                target_changeset_id: target_changeset_id.to_string(),
            })?;

        if head_id == target_changeset_id {
            return Err(VersioningError::InvalidRollbackTarget {
                repo_id: repo_id.to_string(),
                branch: branch.to_string(),
                target_changeset_id: target_changeset_id.to_string(),
            });
        }

        if !branch_state
            .history
            .iter()
            .any(|id| id == target_changeset_id)
        {
            return Err(VersioningError::InvalidRollbackTarget {
                repo_id: repo_id.to_string(),
                branch: branch.to_string(),
                target_changeset_id: target_changeset_id.to_string(),
            });
        }

        let current = repo.snapshots.get(&head_id).cloned().unwrap_or_default();
        let target = repo
            .snapshots
            .get(target_changeset_id)
            .cloned()
            .ok_or_else(|| VersioningError::ChangesetNotFound {
                repo_id: repo_id.to_string(),
                changeset_id: target_changeset_id.to_string(),
            })?;

        let mut asset_ids = BTreeSet::new();
        current.keys().for_each(|k| {
            asset_ids.insert(k.clone());
        });
        target.keys().for_each(|k| {
            asset_ids.insert(k.clone());
        });

        let mut assets = Vec::new();
        for asset_id in asset_ids {
            let current_asset = current.get(&asset_id);
            let target_asset = target.get(&asset_id);
            let current_hash = current_asset.map(|asset| asset.blob_hash.as_str());
            let target_hash = target_asset.map(|asset| asset.blob_hash.as_str());
            if current_hash == target_hash {
                continue;
            }
            assets.push(AssetDelta {
                asset_id: Some(asset_id.clone()),
                path: target_asset
                    .map(|asset| asset.path.clone())
                    .or_else(|| current_asset.map(|asset| asset.path.clone()))
                    .unwrap_or(asset_id),
                from_blob_hash: current_asset.map(|asset| asset.blob_hash.clone()),
                blob_hash: target_asset.map(|asset| asset.blob_hash.clone()),
            });
        }

        Ok(RollbackPlan {
            repo_id: repo_id.to_string(),
            branch: branch.to_string(),
            base_changeset_id: head_id,
            target_changeset_id: target_changeset_id.to_string(),
            assets,
        })
    }

    pub fn sync_snapshot(
        &self,
        repo_id: &str,
        branch: &str,
        to_changeset_id: Option<&str>,
    ) -> Result<SyncSnapshot, VersioningError> {
        let repos = self.repos.read().expect("versioning lock poisoned");
        let repo = repos
            .get(repo_id)
            .ok_or_else(|| VersioningError::RepoNotFound {
                repo_id: repo_id.to_string(),
            })?;
        let branch_state =
            repo.branches
                .get(branch)
                .ok_or_else(|| VersioningError::BranchNotFound {
                    repo_id: repo_id.to_string(),
                    branch: branch.to_string(),
                })?;

        let chosen = if let Some(id) = to_changeset_id {
            if !branch_state.history.iter().any(|entry| entry == id) {
                return Err(VersioningError::ChangesetNotFound {
                    repo_id: repo_id.to_string(),
                    changeset_id: id.to_string(),
                });
            }
            Some(id.to_string())
        } else {
            branch_state.record.head_changeset_id.clone()
        };

        let snapshot_map = chosen
            .as_ref()
            .and_then(|id| repo.snapshots.get(id))
            .cloned()
            .unwrap_or_default();
        let mut assets: Vec<SnapshotEntry> = snapshot_map
            .into_iter()
            .map(|(asset_id, asset)| SnapshotEntry {
                asset_id,
                path: asset.path,
                blob_hash: asset.blob_hash,
            })
            .collect();
        assets.sort_by(|a, b| {
            a.path
                .cmp(&b.path)
                .then_with(|| a.asset_id.cmp(&b.asset_id))
        });

        Ok(SyncSnapshot {
            repo_id: repo_id.to_string(),
            branch: branch.to_string(),
            changeset_id: chosen,
            assets,
        })
    }

    fn submit_internal(
        repo: &mut RepoState,
        input: SubmitChangesetInput,
    ) -> Result<ChangesetRecord, VersioningError> {
        let SubmitChangesetInput {
            repo_id,
            branch,
            base_changeset_id,
            kind,
            rollback_of,
            author,
            message,
            visibility,
            intent_id,
            task_id,
            agent_run_id,
            session_id,
            parent_checkpoint_id,
            risk_level,
            semantic_summary,
            assets,
        } = input;

        if base_changeset_id.is_none() {
            return Err(VersioningError::BaseChangesetRequired);
        }

        let branch_state =
            repo.branches
                .get_mut(&branch)
                .ok_or_else(|| VersioningError::BranchNotFound {
                    repo_id: repo_id.clone(),
                    branch: branch.clone(),
                })?;

        let expected = branch_state.record.head_changeset_id.clone();
        if expected.is_none() {
            if base_changeset_id.as_deref() != Some(ROOT_BASE_CHANGESET_ID) {
                return Err(VersioningError::BaseChangesetMismatch {
                    repo_id,
                    branch,
                    expected,
                    got: base_changeset_id,
                });
            }
        } else if base_changeset_id != expected {
            return Err(VersioningError::BaseChangesetMismatch {
                repo_id,
                branch,
                expected,
                got: base_changeset_id,
            });
        }

        let parent_changeset_id = branch_state.record.head_changeset_id.clone();
        let mut new_snapshot = parent_changeset_id
            .as_ref()
            .and_then(|id| repo.snapshots.get(id))
            .cloned()
            .unwrap_or_default();

        let mut normalized_assets = Vec::with_capacity(assets.len());
        for mut asset in assets {
            let asset_id = asset.asset_id.clone().unwrap_or_else(|| asset.path.clone());
            asset.asset_id = Some(asset_id.clone());
            asset.from_blob_hash = new_snapshot
                .get(&asset_id)
                .map(|snapshot_asset| snapshot_asset.blob_hash.clone());

            if let Some(hash) = &asset.blob_hash {
                new_snapshot.insert(
                    asset_id.clone(),
                    SnapshotAsset {
                        asset_id,
                        path: asset.path.clone(),
                        blob_hash: hash.clone(),
                    },
                );
            } else {
                new_snapshot.remove(&asset_id);
            }
            normalized_assets.push(asset);
        }
        Self::validate_snapshot_layout(&repo_id, &new_snapshot)?;

        let changeset_id = Uuid::new_v4().to_string();
        let status = match visibility {
            ChangesetVisibility::Visible => ChangesetStatus::Visible,
            ChangesetVisibility::Draft => ChangesetStatus::Draft,
        };
        let staging_ref_value = if status == ChangesetStatus::Draft {
            Some(staging_ref(&repo_id, &branch, &changeset_id))
        } else {
            None
        };
        let visible_ref_value = if status == ChangesetStatus::Visible {
            Some(visible_ref(&branch))
        } else {
            None
        };
        let record = ChangesetRecord {
            changeset_id: changeset_id.clone(),
            repo_id,
            branch: branch.clone(),
            parent_changeset_id,
            base_changeset_id,
            kind,
            rollback_of,
            author,
            message,
            created_at: Utc::now(),
            status,
            approved_by: None,
            approved_at: None,
            promoted_at: None,
            staging_ref: staging_ref_value,
            visible_ref: visible_ref_value,
            intent_id,
            task_id,
            agent_run_id,
            session_id,
            parent_checkpoint_id,
            risk_level,
            semantic_summary,
            assets: normalized_assets,
        };

        repo.snapshots.insert(changeset_id.clone(), new_snapshot);
        repo.changesets.insert(changeset_id.clone(), record.clone());
        if record.status == ChangesetStatus::Visible {
            branch_state.record.head_changeset_id = Some(changeset_id.clone());
            branch_state.history.push(changeset_id);
        }

        Ok(record)
    }

    fn validate_snapshot_layout(
        repo_id: &str,
        snapshot: &HashMap<String, SnapshotAsset>,
    ) -> Result<(), VersioningError> {
        let mut paths = HashSet::with_capacity(snapshot.len());
        for asset in snapshot.values() {
            let normalized = asset.path.replace('\\', "/");
            if !paths.insert(normalized.clone()) {
                return Err(VersioningError::InvalidAssetLayout {
                    repo_id: repo_id.to_string(),
                    message: format!("duplicate asset path: {}", asset.path),
                });
            }
        }
        for path in &paths {
            for (index, byte) in path.bytes().enumerate() {
                if byte == b'/' && paths.contains(&path[..index]) {
                    return Err(VersioningError::InvalidAssetLayout {
                        repo_id: repo_id.to_string(),
                        message: format!(
                            "asset path conflicts with parent asset: {} and {}",
                            &path[..index],
                            path
                        ),
                    });
                }
            }
        }
        Ok(())
    }

    fn load_repos(path: &Path) -> Result<HashMap<String, RepoState>, String> {
        if !path.exists() {
            return Ok(HashMap::new());
        }

        let bytes = std::fs::read(path)
            .map_err(|error| format!("failed to read state file {}: {error}", path.display()))?;
        serde_json::from_slice::<HashMap<String, RepoState>>(&bytes)
            .map_err(|error| format!("failed to parse state file {}: {error}", path.display()))
    }

    async fn persist_repo(
        &self,
        repo_id: &str,
        repos: &HashMap<String, RepoState>,
    ) -> Result<(), String> {
        if let Some(repo_pg) = &self.repo_pg {
            if let Some(state) = repos.get(repo_id) {
                repo_pg
                    .replace_repo_state(repo_id, state)
                    .await
                    .map_err(|error| format!("db persistence failed: {error}"))?;
            }
            return Ok(());
        }

        self.persist_repos_file(repos)
    }

    fn persist_repos_file(&self, repos: &HashMap<String, RepoState>) -> Result<(), String> {
        let Some(path) = self.persistence_path.as_ref() else {
            return Ok(());
        };

        if let Some(parent) = path.parent() {
            if let Err(error) = std::fs::create_dir_all(parent) {
                return Err(format!(
                    "failed to create versioning state dir {}: {}",
                    parent.display(),
                    error
                ));
            }
        }

        let payload = match serde_json::to_vec_pretty(repos) {
            Ok(payload) => payload,
            Err(error) => return Err(format!("failed to serialize versioning state: {error}")),
        };

        let temp_path = path.with_extension("tmp");
        if let Err(error) = std::fs::write(&temp_path, payload) {
            return Err(format!(
                "failed to write versioning temp state {}: {}",
                temp_path.display(),
                error
            ));
        }

        if let Err(error) = replace_state_file(&temp_path, path) {
            return Err(format!(
                "failed to atomically replace versioning state {}: {}",
                path.display(),
                error
            ));
        }
        Ok(())
    }
}

impl Default for VersionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct BranchState {
    record: BranchRecord,
    history: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RepoState {
    default_branch: String,
    branches: HashMap<String, BranchState>,
    changesets: HashMap<String, ChangesetRecord>,
    snapshots: HashMap<String, HashMap<String, SnapshotAsset>>,
}

impl RepoState {
    fn new(created_by: &str) -> Self {
        Self::new_with_default("main", created_by)
    }

    fn new_with_default(default_branch: &str, created_by: &str) -> Self {
        let mut repo = Self {
            default_branch: default_branch.to_string(),
            branches: HashMap::new(),
            changesets: HashMap::new(),
            snapshots: HashMap::new(),
        };
        repo.ensure_default_branch(created_by);
        repo
    }

    fn ensure_default_branch(&mut self, created_by: &str) {
        if self.branches.contains_key(&self.default_branch) {
            return;
        }
        let record = BranchRecord {
            name: self.default_branch.clone(),
            created_by: created_by.to_string(),
            created_at: Utc::now(),
            is_default: true,
            head_changeset_id: None,
        };
        self.branches.insert(
            self.default_branch.clone(),
            BranchState {
                record,
                history: Vec::new(),
            },
        );
    }

    fn default_head(&self) -> Option<String> {
        self.branches
            .get(&self.default_branch)
            .and_then(|branch| branch.record.head_changeset_id.clone())
    }

    fn lineage_to(&self, changeset_id: &str) -> Option<Vec<String>> {
        let mut chain = Vec::new();
        let mut current = Some(changeset_id.to_string());
        while let Some(id) = current {
            let node = self.changesets.get(&id)?;
            chain.push(id);
            current = node.parent_changeset_id.clone();
        }
        chain.reverse();
        Some(chain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn submit_with_head_match_advances_branch_head() {
        let manager = VersionManager::new();

        let c1 = manager
            .submit_changeset(SubmitChangesetInput {
                repo_id: "repo-a".to_string(),
                branch: "main".to_string(),
                base_changeset_id: Some(ROOT_BASE_CHANGESET_ID.to_string()),
                kind: ChangesetKind::Normal,
                rollback_of: None,
                author: "alice".to_string(),
                message: "first".to_string(),
                visibility: ChangesetVisibility::Visible,
                intent_id: None,
                task_id: None,
                agent_run_id: None,
                session_id: None,
                parent_checkpoint_id: None,
                risk_level: None,
                semantic_summary: None,
                assets: vec![AssetDelta {
                    asset_id: None,
                    path: "a.txt".to_string(),
                    from_blob_hash: None,
                    blob_hash: Some("hash-1".to_string()),
                }],
            })
            .await
            .expect("first commit should succeed");

        let c2 = manager
            .submit_changeset(SubmitChangesetInput {
                repo_id: "repo-a".to_string(),
                branch: "main".to_string(),
                base_changeset_id: Some(c1.changeset_id.clone()),
                kind: ChangesetKind::Normal,
                rollback_of: None,
                author: "alice".to_string(),
                message: "second".to_string(),
                visibility: ChangesetVisibility::Visible,
                intent_id: None,
                task_id: None,
                agent_run_id: None,
                session_id: None,
                parent_checkpoint_id: None,
                risk_level: None,
                semantic_summary: None,
                assets: vec![AssetDelta {
                    asset_id: None,
                    path: "a.txt".to_string(),
                    from_blob_hash: None,
                    blob_hash: Some("hash-2".to_string()),
                }],
            })
            .await
            .expect("second commit should succeed");

        let sync = manager
            .sync_snapshot("repo-a", "main", None)
            .expect("snapshot should exist");
        assert_eq!(sync.changeset_id, Some(c2.changeset_id));
        assert_eq!(sync.assets.len(), 1);
        assert_eq!(sync.assets[0].blob_hash, "hash-2");
    }

    #[tokio::test]
    async fn submit_rejects_conflicting_snapshot_paths() {
        let manager = VersionManager::new();
        let error = manager
            .submit_changeset(SubmitChangesetInput {
                repo_id: "repo-layout".to_string(),
                branch: "main".to_string(),
                base_changeset_id: Some(ROOT_BASE_CHANGESET_ID.to_string()),
                kind: ChangesetKind::Normal,
                rollback_of: None,
                author: "alice".to_string(),
                message: "invalid layout".to_string(),
                visibility: ChangesetVisibility::Visible,
                intent_id: None,
                task_id: None,
                agent_run_id: None,
                session_id: None,
                parent_checkpoint_id: None,
                risk_level: None,
                semantic_summary: None,
                assets: vec![
                    AssetDelta {
                        asset_id: Some("asset-parent".to_string()),
                        path: "Content".to_string(),
                        from_blob_hash: None,
                        blob_hash: Some("hash-parent".to_string()),
                    },
                    AssetDelta {
                        asset_id: Some("asset-child".to_string()),
                        path: "Content/A.uasset".to_string(),
                        from_blob_hash: None,
                        blob_hash: Some("hash-child".to_string()),
                    },
                ],
            })
            .await
            .expect_err("conflicting paths must be rejected");

        assert!(matches!(error, VersioningError::InvalidAssetLayout { .. }));
        assert!(manager.list_repos().is_empty());
    }

    #[tokio::test]
    async fn create_repo_creates_default_branch_and_rejects_duplicates() {
        let manager = VersionManager::new();

        let repo = manager
            .create_repo("repo-explicit", "main", "alice")
            .await
            .expect("repo should be created");

        assert_eq!(repo.repo_id, "repo-explicit");
        assert_eq!(repo.default_branch, "main");
        assert_eq!(repo.branch_count, 1);
        assert_eq!(repo.default_head_changeset_id, None);

        let duplicate = manager
            .create_repo("repo-explicit", "main", "alice")
            .await
            .expect_err("duplicate repo should fail");

        assert_eq!(
            duplicate,
            VersioningError::RepoAlreadyExists {
                repo_id: "repo-explicit".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn list_and_get_repo_info_return_default_branch() {
        let manager = VersionManager::new();

        manager
            .create_repo("repo-info", "main", "alice")
            .await
            .expect("repo should be created");

        let repos = manager.list_repos();
        assert_eq!(repos.len(), 1);
        assert_eq!(repos[0].repo_id, "repo-info");
        assert_eq!(repos[0].default_branch, "main");

        let info = manager
            .get_repo_info("repo-info")
            .expect("repo info should exist");
        assert_eq!(info.branches.len(), 1);
        assert_eq!(info.branches[0].name, "main");
        assert!(info.branches[0].is_default);
    }

    #[tokio::test]
    async fn stale_base_is_rejected() {
        let manager = VersionManager::new();

        let c1 = manager
            .submit_changeset(SubmitChangesetInput {
                repo_id: "repo-b".to_string(),
                branch: "main".to_string(),
                base_changeset_id: Some(ROOT_BASE_CHANGESET_ID.to_string()),
                kind: ChangesetKind::Normal,
                rollback_of: None,
                author: "alice".to_string(),
                message: "first".to_string(),
                visibility: ChangesetVisibility::Visible,
                intent_id: None,
                task_id: None,
                agent_run_id: None,
                session_id: None,
                parent_checkpoint_id: None,
                risk_level: None,
                semantic_summary: None,
                assets: vec![],
            })
            .await
            .expect("first should succeed");

        let c2 = manager
            .submit_changeset(SubmitChangesetInput {
                repo_id: "repo-b".to_string(),
                branch: "main".to_string(),
                base_changeset_id: Some(ROOT_BASE_CHANGESET_ID.to_string()),
                kind: ChangesetKind::Normal,
                rollback_of: None,
                author: "alice".to_string(),
                message: "invalid".to_string(),
                visibility: ChangesetVisibility::Visible,
                intent_id: None,
                task_id: None,
                agent_run_id: None,
                session_id: None,
                parent_checkpoint_id: None,
                risk_level: None,
                semantic_summary: None,
                assets: vec![],
            })
            .await
            .expect_err("stale base must fail");

        assert_eq!(
            c2,
            VersioningError::BaseChangesetMismatch {
                repo_id: "repo-b".to_string(),
                branch: "main".to_string(),
                expected: Some(c1.changeset_id),
                got: Some(ROOT_BASE_CHANGESET_ID.to_string()),
            }
        );
    }

    #[tokio::test]
    async fn rollback_plan_targets_existing_history() {
        let manager = VersionManager::new();
        let c1 = manager
            .submit_changeset(SubmitChangesetInput {
                repo_id: "repo-c".to_string(),
                branch: "main".to_string(),
                base_changeset_id: Some(ROOT_BASE_CHANGESET_ID.to_string()),
                kind: ChangesetKind::Normal,
                rollback_of: None,
                author: "alice".to_string(),
                message: "first".to_string(),
                visibility: ChangesetVisibility::Visible,
                intent_id: None,
                task_id: None,
                agent_run_id: None,
                session_id: None,
                parent_checkpoint_id: None,
                risk_level: None,
                semantic_summary: None,
                assets: vec![AssetDelta {
                    asset_id: None,
                    path: "a".to_string(),
                    from_blob_hash: None,
                    blob_hash: Some("h1".to_string()),
                }],
            })
            .await
            .expect("first commit");

        let c2 = manager
            .submit_changeset(SubmitChangesetInput {
                repo_id: "repo-c".to_string(),
                branch: "main".to_string(),
                base_changeset_id: Some(c1.changeset_id.clone()),
                kind: ChangesetKind::Normal,
                rollback_of: None,
                author: "alice".to_string(),
                message: "second".to_string(),
                visibility: ChangesetVisibility::Visible,
                intent_id: None,
                task_id: None,
                agent_run_id: None,
                session_id: None,
                parent_checkpoint_id: None,
                risk_level: None,
                semantic_summary: None,
                assets: vec![AssetDelta {
                    asset_id: None,
                    path: "a".to_string(),
                    from_blob_hash: None,
                    blob_hash: Some("h2".to_string()),
                }],
            })
            .await
            .expect("second commit");

        let plan = manager
            .build_rollback_plan("repo-c", "main", &c1.changeset_id)
            .expect("rollback plan");
        assert_eq!(plan.base_changeset_id, c2.changeset_id.clone());
        assert_eq!(plan.assets.len(), 1);
        assert_eq!(plan.assets[0].blob_hash.as_deref(), Some("h1"));

        manager
            .submit_changeset(SubmitChangesetInput {
                repo_id: "repo-c".to_string(),
                branch: "main".to_string(),
                base_changeset_id: Some(plan.base_changeset_id.clone()),
                kind: ChangesetKind::Rollback,
                rollback_of: Some(plan.target_changeset_id),
                author: "alice".to_string(),
                message: "rollback".to_string(),
                visibility: ChangesetVisibility::Visible,
                intent_id: None,
                task_id: None,
                agent_run_id: None,
                session_id: None,
                parent_checkpoint_id: None,
                risk_level: None,
                semantic_summary: None,
                assets: plan.assets,
            })
            .await
            .expect("rollback commit should be accepted");

        let sync = manager
            .sync_snapshot("repo-c", "main", None)
            .expect("snapshot");
        assert_eq!(sync.assets[0].blob_hash, "h1");
    }

    #[tokio::test]
    async fn draft_changeset_uses_staging_ref_and_promote_sets_visible_ref() {
        let manager = VersionManager::new();

        let base = manager
            .submit_changeset(SubmitChangesetInput {
                repo_id: "repo-gate".to_string(),
                branch: "main".to_string(),
                base_changeset_id: Some(ROOT_BASE_CHANGESET_ID.to_string()),
                kind: ChangesetKind::Normal,
                rollback_of: None,
                author: "alice".to_string(),
                message: "base".to_string(),
                visibility: ChangesetVisibility::Visible,
                intent_id: None,
                task_id: None,
                agent_run_id: None,
                session_id: None,
                parent_checkpoint_id: None,
                risk_level: None,
                semantic_summary: None,
                assets: vec![],
            })
            .await
            .expect("base changeset");

        let draft = manager
            .submit_changeset(SubmitChangesetInput {
                repo_id: "repo-gate".to_string(),
                branch: "main".to_string(),
                base_changeset_id: Some(base.changeset_id.clone()),
                kind: ChangesetKind::Normal,
                rollback_of: None,
                author: "alice".to_string(),
                message: "draft".to_string(),
                visibility: ChangesetVisibility::Draft,
                intent_id: None,
                task_id: None,
                agent_run_id: None,
                session_id: None,
                parent_checkpoint_id: None,
                risk_level: None,
                semantic_summary: None,
                assets: vec![],
            })
            .await
            .expect("draft changeset");

        assert!(draft.staging_ref.is_some());
        assert_eq!(draft.visible_ref, None);

        let approved = manager
            .approve_changeset("repo-gate", &draft.changeset_id, "reviewer")
            .await
            .expect("approve draft");
        assert_eq!(approved.visible_ref, None);

        let promoted = manager
            .promote_changeset("repo-gate", &draft.changeset_id, "release-bot")
            .await
            .expect("promote approved");
        assert_eq!(promoted.visible_ref.as_deref(), Some("refs/heads/main"));
        assert!(promoted.staging_ref.is_some());
    }

    #[tokio::test]
    async fn changeset_gate_requires_approved_before_promote() {
        let manager = VersionManager::new();

        let base = manager
            .submit_changeset(SubmitChangesetInput {
                repo_id: "repo-gate-2".to_string(),
                branch: "main".to_string(),
                base_changeset_id: Some(ROOT_BASE_CHANGESET_ID.to_string()),
                kind: ChangesetKind::Normal,
                rollback_of: None,
                author: "alice".to_string(),
                message: "base".to_string(),
                visibility: ChangesetVisibility::Visible,
                intent_id: None,
                task_id: None,
                agent_run_id: None,
                session_id: None,
                parent_checkpoint_id: None,
                risk_level: None,
                semantic_summary: None,
                assets: vec![],
            })
            .await
            .expect("base changeset");

        let draft = manager
            .submit_changeset(SubmitChangesetInput {
                repo_id: "repo-gate-2".to_string(),
                branch: "main".to_string(),
                base_changeset_id: Some(base.changeset_id.clone()),
                kind: ChangesetKind::Normal,
                rollback_of: None,
                author: "alice".to_string(),
                message: "draft".to_string(),
                visibility: ChangesetVisibility::Draft,
                intent_id: None,
                task_id: None,
                agent_run_id: None,
                session_id: None,
                parent_checkpoint_id: None,
                risk_level: None,
                semantic_summary: None,
                assets: vec![],
            })
            .await
            .expect("draft changeset");

        let gate_before = manager
            .changeset_gate("repo-gate-2", &draft.changeset_id)
            .expect("gate for draft");
        assert!(!gate_before.can_promote);
        assert_eq!(gate_before.required_state, "approved");

        manager
            .approve_changeset("repo-gate-2", &draft.changeset_id, "reviewer")
            .await
            .expect("approve draft");

        let gate_after = manager
            .changeset_gate("repo-gate-2", &draft.changeset_id)
            .expect("gate for approved");
        assert!(gate_after.can_promote);
        assert_eq!(gate_after.required_state, "approved");
    }

    #[tokio::test]
    async fn submit_preserves_agent_session_metadata() {
        let manager = VersionManager::new();

        let changeset = manager
            .submit_changeset(SubmitChangesetInput {
                repo_id: "repo-agent-meta".to_string(),
                branch: "main".to_string(),
                base_changeset_id: Some(ROOT_BASE_CHANGESET_ID.to_string()),
                kind: ChangesetKind::Normal,
                rollback_of: None,
                author: "agent-a".to_string(),
                message: "draft from checkpoint".to_string(),
                visibility: ChangesetVisibility::Draft,
                intent_id: Some("intent-1".to_string()),
                task_id: Some("task-1".to_string()),
                agent_run_id: Some("run-1".to_string()),
                session_id: Some("session-1".to_string()),
                parent_checkpoint_id: Some("checkpoint-1".to_string()),
                risk_level: Some("local".to_string()),
                semantic_summary: Some("inventory implementation draft".to_string()),
                assets: vec![],
            })
            .await
            .expect("draft changeset");

        assert_eq!(changeset.status, ChangesetStatus::Draft);
        assert_eq!(changeset.intent_id.as_deref(), Some("intent-1"));
        assert_eq!(changeset.task_id.as_deref(), Some("task-1"));
        assert_eq!(changeset.agent_run_id.as_deref(), Some("run-1"));
        assert_eq!(changeset.session_id.as_deref(), Some("session-1"));
        assert_eq!(
            changeset.parent_checkpoint_id.as_deref(),
            Some("checkpoint-1")
        );
        assert_eq!(changeset.risk_level.as_deref(), Some("local"));
        assert_eq!(
            changeset.semantic_summary.as_deref(),
            Some("inventory implementation draft")
        );
    }

    #[tokio::test]
    async fn persists_state_across_manager_restarts() {
        let state_file =
            std::env::temp_dir().join(format!("hypertide-versioning-{}.json", Uuid::new_v4()));

        let first_manager = VersionManager::with_persistence(&state_file);
        first_manager
            .submit_changeset(SubmitChangesetInput {
                repo_id: "repo-p".to_string(),
                branch: "main".to_string(),
                base_changeset_id: Some(ROOT_BASE_CHANGESET_ID.to_string()),
                kind: ChangesetKind::Normal,
                rollback_of: None,
                author: "alice".to_string(),
                message: "first".to_string(),
                visibility: ChangesetVisibility::Visible,
                intent_id: None,
                task_id: None,
                agent_run_id: None,
                session_id: None,
                parent_checkpoint_id: None,
                risk_level: None,
                semantic_summary: None,
                assets: vec![AssetDelta {
                    asset_id: None,
                    path: "env/config.json".to_string(),
                    from_blob_hash: None,
                    blob_hash: Some("blob-v1".to_string()),
                }],
            })
            .await
            .expect("submit should persist");

        let second_manager = VersionManager::with_persistence(&state_file);
        let snapshot = second_manager
            .sync_snapshot("repo-p", "main", None)
            .expect("snapshot should load from persistence");
        assert_eq!(snapshot.assets.len(), 1);
        assert_eq!(snapshot.assets[0].path, "env/config.json");
        assert_eq!(snapshot.assets[0].blob_hash, "blob-v1");

        let _ = std::fs::remove_file(state_file);
    }

    #[tokio::test]
    async fn persistence_failure_does_not_publish_in_memory_state() {
        let blocker =
            std::env::temp_dir().join(format!("hypertide-versioning-blocker-{}", Uuid::new_v4()));
        std::fs::write(&blocker, b"not-a-directory").expect("create blocker");
        let manager = VersionManager::with_persistence(blocker.join("state.json"));

        let error = manager
            .create_repo("repo-not-persisted", "main", "alice")
            .await
            .expect_err("persistence must fail");

        assert!(matches!(error, VersioningError::Persistence { .. }));
        assert!(manager.list_repos().is_empty());
        let _ = std::fs::remove_file(blocker);
    }

    #[tokio::test]
    async fn file_persistence_supports_consecutive_mutations() {
        let state_file =
            std::env::temp_dir().join(format!("hypertide-versioning-{}.json", Uuid::new_v4()));
        let manager = VersionManager::with_persistence(&state_file);

        manager
            .create_repo("repo-p", "main", "alice")
            .await
            .expect("first persistence write");
        manager
            .create_branch("repo-p", "feature", None, "alice")
            .await
            .expect("replacement persistence write");

        let reloaded = VersionManager::with_persistence(&state_file);
        let branches = reloaded
            .list_branches("repo-p")
            .expect("load persisted repo");
        assert_eq!(branches.len(), 2);
        assert!(branches.iter().any(|branch| branch.name == "feature"));

        let _ = std::fs::remove_file(state_file);
    }
}
