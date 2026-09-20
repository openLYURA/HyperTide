use std::{collections::HashSet, fs, path::Path};

use anyhow::{anyhow, Context, Result};
use clap::Args;

use crate::utils::*;

#[derive(Debug, Args)]
pub(crate) struct SyncArgs {
    #[arg(long, help = "Repository id; defaults to the login profile repository")]
    pub repo: Option<String>,
    #[arg(long, help = "Branch to sync; defaults to the login profile branch")]
    pub branch: Option<String>,
    #[arg(long = "to", help = "Optional changeset id to sync to")]
    pub to_changeset_id: Option<String>,
    #[arg(long, help = "Force sync, overwriting local modifications")]
    pub force: bool,
}

pub(crate) async fn execute(args: SyncArgs) -> Result<()> {
    let mut profile = load_profile()?;
    let repo = resolve_repo(&profile, args.repo.as_deref())?;
    let branch = args
        .branch
        .unwrap_or_else(|| profile.current_branch.clone());
    let workspace_root = std::env::current_dir()?;
    let client = reqwest::Client::new();
    let snapshot = fetch_snapshot(
        &client,
        &mut profile,
        &repo,
        &branch,
        args.to_changeset_id.as_deref(),
    )
    .await?;

    let existing_workspace = load_workspace().ok().filter(|workspace| {
        workspace.repo_id == repo
            && workspace.branch == branch
            && Path::new(&workspace.workspace_root) == workspace_root
    });

    // A base-pointer advance without reconciling file content silently discards
    // intervening changes on the next submit. Refuse when local work would be
    // clobbered so the user resolves it (submit / --force) rather than losing it.
    if !args.force {
        if let Ok(stage) = load_stage() {
            if !stage.assets.is_empty() {
                return Err(anyhow!(
                    "workspace has {} staged change(s); submit them before syncing or use --force",
                    stage.assets.len()
                ));
            }
        }
        if let Some(workspace) = &existing_workspace {
            let conflicts = detect_local_modifications(workspace)?;
            if !conflicts.is_empty() {
                eprintln!(
                    "error: workspace has {} uncommitted modification(s); sync would overwrite:",
                    conflicts.len()
                );
                for conflict in &conflicts {
                    eprintln!("  {}", conflict.path);
                }
                eprintln!("submit your changes, or re-run with --force to overwrite.");
                return Err(anyhow!("sync refused to overwrite local changes"));
            }
        }
    }

    let snapshot_paths = snapshot
        .assets
        .iter()
        .map(|asset| asset.path.as_str())
        .collect::<HashSet<_>>();

    // Guard against overwriting untracked local files that collide with the snapshot.
    let tracked_paths = existing_workspace
        .as_ref()
        .map(|workspace| {
            workspace
                .checked_out_assets
                .iter()
                .map(|asset| asset.path.as_str())
                .collect::<HashSet<_>>()
        })
        .unwrap_or_default();
    if !args.force {
        for asset in &snapshot.assets {
            if tracked_paths.contains(asset.path.as_str()) {
                continue;
            }
            let target = resolve_workspace_target(&workspace_root, &asset.path)?;
            if target.exists()
                && (target.is_dir()
                    || hash_local_asset(&workspace_root, &asset.path)?.as_deref()
                        != Some(asset.blob_hash.as_str()))
            {
                return Err(anyhow!(
                    "sync would overwrite untracked local file {}; use --force",
                    asset.path
                ));
            }
        }
    }

    // Remove tracked files that no longer exist in the new snapshot.
    if let Some(workspace) = &existing_workspace {
        for asset in &workspace.checked_out_assets {
            if snapshot_paths.contains(asset.path.as_str()) {
                continue;
            }
            let target = resolve_workspace_target(&workspace_root, &asset.path)?;
            if target.is_file() {
                fs::remove_file(&target)
                    .with_context(|| format!("failed to delete {}", target.display()))?;
            }
        }
    }

    // Materialize snapshot content so recorded hashes and on-disk files agree with
    // the advanced base pointer.
    let mut checked_out_assets = Vec::with_capacity(snapshot.assets.len());
    for asset in &snapshot.assets {
        let target = resolve_workspace_target(&workspace_root, &asset.path)?;
        let bytes = fetch_blob_bytes(&client, &mut profile, &asset.blob_hash).await?;
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&target, &bytes)
            .with_context(|| format!("failed to write {}", target.display()))?;
        checked_out_assets.push(WorkspaceFile {
            path: asset.path.clone(),
            blob_hash: asset.blob_hash.clone(),
            asset_id: asset.asset_id.clone(),
        });
    }

    let workspace = WorkspaceState {
        repo_id: repo.clone(),
        branch: branch.clone(),
        workspace_root: workspace_root.to_string_lossy().to_string(),
        base_changeset_id: snapshot.changeset_id.clone(),
        checked_out_assets,
        last_synced_at: now_unix(),
    };
    save_workspace(&workspace)?;

    // Advance the base pointer; a clean workspace now has no staged assets.
    let mut stage = StageFile::default_for_branch(&branch);
    stage.base_changeset_id = snapshot.changeset_id.clone();
    save_stage(&stage)?;

    println!(
        "synced {}@{} to {} ({} assets)",
        repo,
        branch,
        snapshot
            .changeset_id
            .clone()
            .unwrap_or_else(|| "ROOT".to_string()),
        snapshot.assets.len()
    );
    Ok(())
}
