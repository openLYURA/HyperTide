use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use sqlx::{FromRow, PgPool};

use crate::core::versioning::{
    AssetDelta, BranchRecord, BranchState, ChangesetKind, ChangesetRecord, ChangesetStatus,
    RepoState, SnapshotAsset,
};

#[derive(Clone)]
pub struct VersionRepoPg {
    pool: PgPool,
    /// Per-repo `state_version` last observed by this process. Used as the expected
    /// value in the optimistic-concurrency guard so a concurrent writer's update is
    /// detected instead of silently overwritten.
    versions: Arc<DashMap<String, i64>>,
}

#[derive(Debug, FromRow)]
struct RepoRow {
    repo_id: String,
    created_by: String,
    state_version: i64,
}

#[derive(Debug, FromRow)]
struct BranchRow {
    branch_name: String,
    head_changeset_id: Option<String>,
    created_by: String,
    created_at: DateTime<Utc>,
    is_default: bool,
}

#[derive(Debug, FromRow)]
struct ChangesetRow {
    changeset_id: String,
    repo_id: String,
    branch_name: String,
    parent_changeset_id: Option<String>,
    base_changeset_id: Option<String>,
    kind: String,
    rollback_of: Option<String>,
    author: String,
    message: String,
    created_at: DateTime<Utc>,
    status: String,
    approved_by: Option<String>,
    approved_at: Option<DateTime<Utc>>,
    promoted_at: Option<DateTime<Utc>>,
    staging_ref: Option<String>,
    visible_ref: Option<String>,
    intent_id: Option<String>,
    task_id: Option<String>,
    agent_run_id: Option<String>,
    session_id: Option<String>,
    parent_checkpoint_id: Option<String>,
    risk_level: Option<String>,
    semantic_summary: Option<String>,
}

#[derive(Debug, FromRow)]
struct AssetDeltaRow {
    changeset_id: String,
    asset_id: Option<String>,
    path: String,
    from_blob_hash: Option<String>,
    to_blob_hash: Option<String>,
    blob_hash: Option<String>,
}

#[derive(Debug, FromRow)]
struct SnapshotRow {
    changeset_id: String,
    asset_id: Option<String>,
    path: String,
    blob_hash: String,
}

impl VersionRepoPg {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            versions: Arc::new(DashMap::new()),
        }
    }

    pub(super) async fn load_repos(&self) -> Result<HashMap<String, RepoState>, sqlx::Error> {
        let mut repos = HashMap::new();

        let repo_rows = sqlx::query_as::<_, RepoRow>(
            r#"
            SELECT repo_id, created_by, state_version
            FROM repos
            ORDER BY created_at ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        for repo_row in repo_rows {
            self.versions
                .insert(repo_row.repo_id.clone(), repo_row.state_version);
            let mut repo = RepoState {
                default_branch: "main".to_string(),
                branches: HashMap::new(),
                changesets: HashMap::new(),
                snapshots: HashMap::new(),
            };

            let branch_rows = sqlx::query_as::<_, BranchRow>(
                r#"
                SELECT branch_name, head_changeset_id, created_by, created_at, is_default
                FROM branches
                WHERE repo_id = $1
                ORDER BY created_at ASC
                "#,
            )
            .bind(&repo_row.repo_id)
            .fetch_all(&self.pool)
            .await?;

            for branch_row in branch_rows {
                let branch_name = branch_row.branch_name.clone();
                if branch_row.is_default {
                    repo.default_branch = branch_name.clone();
                }

                repo.branches.insert(
                    branch_name.clone(),
                    BranchState {
                        record: BranchRecord {
                            name: branch_name,
                            created_by: branch_row.created_by,
                            created_at: branch_row.created_at,
                            is_default: branch_row.is_default,
                            head_changeset_id: branch_row.head_changeset_id,
                        },
                        history: Vec::new(),
                    },
                );
            }

            if repo.branches.is_empty() {
                repo.ensure_default_branch(&repo_row.created_by);
            }

            let changeset_rows = sqlx::query_as::<_, ChangesetRow>(
                r#"
                SELECT changeset_id, repo_id, branch_name, parent_changeset_id, base_changeset_id, kind, rollback_of, author, message, created_at, status, approved_by, approved_at, promoted_at
                       , staging_ref, visible_ref, intent_id, task_id, agent_run_id, session_id, parent_checkpoint_id, risk_level, semantic_summary
                FROM changesets
                WHERE repo_id = $1
                ORDER BY created_at ASC
                "#,
            )
            .bind(&repo_row.repo_id)
            .fetch_all(&self.pool)
            .await?;

            for row in changeset_rows {
                repo.changesets.insert(
                    row.changeset_id.clone(),
                    ChangesetRecord {
                        changeset_id: row.changeset_id,
                        repo_id: row.repo_id,
                        branch: row.branch_name,
                        parent_changeset_id: row.parent_changeset_id,
                        base_changeset_id: row.base_changeset_id,
                        kind: parse_kind(&row.kind),
                        rollback_of: row.rollback_of,
                        author: row.author,
                        message: row.message,
                        created_at: row.created_at,
                        status: parse_status(&row.status),
                        approved_by: row.approved_by,
                        approved_at: row.approved_at,
                        promoted_at: row.promoted_at,
                        staging_ref: row.staging_ref,
                        visible_ref: row.visible_ref,
                        intent_id: row.intent_id,
                        task_id: row.task_id,
                        agent_run_id: row.agent_run_id,
                        session_id: row.session_id,
                        parent_checkpoint_id: row.parent_checkpoint_id,
                        risk_level: row.risk_level,
                        semantic_summary: row.semantic_summary,
                        assets: Vec::new(),
                    },
                );
            }

            let delta_rows = sqlx::query_as::<_, AssetDeltaRow>(
                r#"
                SELECT d.changeset_id, d.asset_id, d.path, d.from_blob_hash, d.to_blob_hash, d.blob_hash
                FROM asset_deltas d
                INNER JOIN changesets c ON c.changeset_id = d.changeset_id
                WHERE c.repo_id = $1
                ORDER BY d.id ASC
                "#,
            )
            .bind(&repo_row.repo_id)
            .fetch_all(&self.pool)
            .await?;

            for delta in delta_rows {
                if let Some(changeset) = repo.changesets.get_mut(&delta.changeset_id) {
                    changeset.assets.push(AssetDelta {
                        asset_id: delta.asset_id,
                        path: delta.path,
                        from_blob_hash: delta.from_blob_hash,
                        blob_hash: delta.to_blob_hash.or(delta.blob_hash),
                    });
                }
            }

            let snapshot_rows = sqlx::query_as::<_, SnapshotRow>(
                r#"
                SELECT changeset_id, asset_id, path, blob_hash
                FROM snapshots
                WHERE repo_id = $1
                ORDER BY id ASC
                "#,
            )
            .bind(&repo_row.repo_id)
            .fetch_all(&self.pool)
            .await?;

            for row in snapshot_rows {
                let asset_id = row.asset_id.unwrap_or_else(|| row.path.clone());
                repo.snapshots.entry(row.changeset_id).or_default().insert(
                    asset_id.clone(),
                    SnapshotAsset {
                        asset_id,
                        path: row.path,
                        blob_hash: row.blob_hash,
                    },
                );
            }

            let branch_heads = repo
                .branches
                .iter()
                .map(|(name, state)| (name.clone(), state.record.head_changeset_id.clone()))
                .collect::<Vec<_>>();
            for (name, head) in branch_heads {
                let history = head
                    .as_deref()
                    .and_then(|head_id| repo.lineage_to(head_id))
                    .unwrap_or_default();
                if let Some(state) = repo.branches.get_mut(&name) {
                    state.history = history;
                }
            }

            repos.insert(repo_row.repo_id, repo);
        }

        Ok(repos)
    }

    pub(super) async fn replace_repo_state(
        &self,
        repo_id: &str,
        repo: &RepoState,
    ) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;

        let created_by = repo
            .branches
            .get(&repo.default_branch)
            .map(|state| state.record.created_by.as_str())
            .or_else(|| {
                repo.branches
                    .values()
                    .next()
                    .map(|s| s.record.created_by.as_str())
            })
            .unwrap_or("system");

        // Optimistic-concurrency guard. `expected` is the version this process last
        // observed for the repo; the guarded write only succeeds if the DB still
        // holds that version, so a concurrent writer (e.g. another instance) that
        // advanced the repo is detected here instead of being silently clobbered.
        let expected_version = self.versions.get(repo_id).map(|entry| *entry);
        let new_version = match expected_version {
            Some(expected) => {
                let updated = sqlx::query(
                    r#"
                    UPDATE repos
                    SET created_by = $2, state_version = state_version + 1
                    WHERE repo_id = $1 AND state_version = $3
                    "#,
                )
                .bind(repo_id)
                .bind(created_by)
                .bind(expected)
                .execute(&mut *tx)
                .await?;
                if updated.rows_affected() == 0 {
                    tx.rollback().await?;
                    return Err(sqlx::Error::Protocol(format!(
                        "concurrent modification of repo {repo_id}: expected state_version {expected}"
                    )));
                }
                expected + 1
            }
            None => {
                let inserted = sqlx::query(
                    r#"
                    INSERT INTO repos (repo_id, created_by, state_version)
                    VALUES ($1, $2, 0)
                    ON CONFLICT (repo_id) DO NOTHING
                    "#,
                )
                .bind(repo_id)
                .bind(created_by)
                .execute(&mut *tx)
                .await?;
                if inserted.rows_affected() == 0 {
                    // The repo already exists in the DB but this process never loaded
                    // or persisted it: another writer owns it. Refuse rather than
                    // overwrite an unknown state.
                    tx.rollback().await?;
                    return Err(sqlx::Error::Protocol(format!(
                        "concurrent creation of repo {repo_id} by another writer"
                    )));
                }
                0
            }
        };

        sqlx::query("DELETE FROM branches WHERE repo_id = $1")
            .bind(repo_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM changesets WHERE repo_id = $1")
            .bind(repo_id)
            .execute(&mut *tx)
            .await?;

        for changeset in repo.changesets.values() {
            sqlx::query(
                r#"
                INSERT INTO changesets (
                    changeset_id, repo_id, branch_name, parent_changeset_id, base_changeset_id, kind, rollback_of, author, message, created_at, status, approved_by, approved_at, promoted_at, staging_ref, visible_ref, intent_id, task_id, agent_run_id, session_id, parent_checkpoint_id, risk_level, semantic_summary
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)
                "#,
            )
            .bind(&changeset.changeset_id)
            .bind(&changeset.repo_id)
            .bind(&changeset.branch)
            .bind(&changeset.parent_changeset_id)
            .bind(&changeset.base_changeset_id)
            .bind(changeset.kind.as_str())
            .bind(&changeset.rollback_of)
            .bind(&changeset.author)
            .bind(&changeset.message)
            .bind(changeset.created_at)
            .bind(changeset.status.as_str())
            .bind(&changeset.approved_by)
            .bind(changeset.approved_at)
            .bind(changeset.promoted_at)
            .bind(&changeset.staging_ref)
            .bind(&changeset.visible_ref)
            .bind(&changeset.intent_id)
            .bind(&changeset.task_id)
            .bind(&changeset.agent_run_id)
            .bind(&changeset.session_id)
            .bind(&changeset.parent_checkpoint_id)
            .bind(&changeset.risk_level)
            .bind(&changeset.semantic_summary)
            .execute(&mut *tx)
            .await?;

            for delta in &changeset.assets {
                sqlx::query(
                    r#"
                    INSERT INTO asset_deltas (changeset_id, asset_id, path, from_blob_hash, to_blob_hash, blob_hash)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    "#,
                )
                .bind(&changeset.changeset_id)
                .bind(delta.asset_id.as_deref().unwrap_or(&delta.path))
                .bind(&delta.path)
                .bind(&delta.from_blob_hash)
                .bind(&delta.blob_hash)
                .bind(&delta.blob_hash)
                .execute(&mut *tx)
                .await?;
            }
        }

        for (changeset_id, snapshot) in &repo.snapshots {
            // Persist each snapshot under the branch its changeset actually belongs
            // to. Binding the default branch unconditionally mislabeled every
            // non-default-branch snapshot (the table is keyed by branch_name).
            let branch_name = repo
                .changesets
                .get(changeset_id)
                .map(|changeset| changeset.branch.as_str())
                .unwrap_or(repo.default_branch.as_str());
            for (asset_id, snapshot_asset) in snapshot {
                sqlx::query(
                    r#"
                    INSERT INTO snapshots (repo_id, branch_name, changeset_id, asset_id, path, blob_hash)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    "#,
                )
                .bind(repo_id)
                .bind(branch_name)
                .bind(changeset_id)
                .bind(asset_id)
                .bind(&snapshot_asset.path)
                .bind(&snapshot_asset.blob_hash)
                .execute(&mut *tx)
                .await?;
            }
        }

        for branch in repo.branches.values() {
            sqlx::query(
                r#"
                INSERT INTO branches (repo_id, branch_name, head_changeset_id, created_by, created_at, is_default)
                VALUES ($1, $2, $3, $4, $5, $6)
                "#,
            )
            .bind(repo_id)
            .bind(&branch.record.name)
            .bind(&branch.record.head_changeset_id)
            .bind(&branch.record.created_by)
            .bind(branch.record.created_at)
            .bind(branch.record.is_default)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        self.versions.insert(repo_id.to_string(), new_version);
        Ok(())
    }
}

fn parse_kind(value: &str) -> ChangesetKind {
    match value {
        "rollback" => ChangesetKind::Rollback,
        _ => ChangesetKind::Normal,
    }
}

fn parse_status(value: &str) -> ChangesetStatus {
    match value {
        "draft" => ChangesetStatus::Draft,
        "approved" => ChangesetStatus::Approved,
        _ => ChangesetStatus::Visible,
    }
}
