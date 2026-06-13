use std::fs;

use anyhow::{Context, Result};
use clap::Args;

use crate::utils::*;

#[derive(Debug, Args)]
pub(crate) struct CheckoutArgs {
    #[arg(long, help = "Repository id; defaults to the login profile repository")]
    pub repo: Option<String>,
    #[arg(
        long,
        help = "Branch to checkout; defaults to the login profile branch"
    )]
    pub branch: Option<String>,
    #[arg(long = "to", help = "Optional changeset id to checkout")]
    pub to_changeset_id: Option<String>,
    #[arg(long, help = "Force checkout, overwriting local modifications")]
    pub force: bool,
    #[arg(long, help = "Preview checkout changes without writing files")]
    pub dry_run: bool,
}

pub(crate) async fn execute(args: CheckoutArgs) -> Result<()> {
    let mut profile = load_profile()?;
    let repo = resolve_repo(&profile, args.repo.as_deref())?;
    let branch = args
        .branch
        .unwrap_or_else(|| profile.current_branch.clone());

    // Pre-check: detect local modifications before overwriting
    if !args.force {
        if let Ok(workspace) = load_workspace() {
            let conflicts = detect_local_modifications(&workspace)?;
            if !conflicts.is_empty() {
                eprintln!(
                    "error: workspace has {} uncommitted modification(s), checkout would overwrite:",
                    conflicts.len()
                );
                for c in &conflicts {
                    eprintln!("  {}", c.path);
                }
                eprintln!(
                    "use 'ht add --file <path>' to stage changes, or use '--force' to overwrite."
                );
                std::process::exit(1);
            }
        }
    }

    let client = reqwest::Client::new();
    let snapshot = fetch_snapshot(
        &client,
        &mut profile,
        &repo,
        &branch,
        args.to_changeset_id.as_deref(),
    )
    .await?;
    if args.dry_run {
        println!(
            "checkout preview {}@{} to {} ({} assets)",
            repo,
            branch,
            snapshot
                .changeset_id
                .clone()
                .unwrap_or_else(|| "ROOT".to_string()),
            snapshot.assets.len()
        );
        for asset in &snapshot.assets {
            println!("  write {} <- {}", asset.path, asset.blob_hash);
        }
        return Ok(());
    }
    let workspace_root = std::env::current_dir()?;
    let mut checked_out_assets = Vec::with_capacity(snapshot.assets.len());

    for asset in &snapshot.assets {
        let target = workspace_root.join(asset.path.replace('/', std::path::MAIN_SEPARATOR_STR));
        let bytes = fetch_blob_bytes(&client, &mut profile, &asset.blob_hash).await?;
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&target, &bytes)
            .with_context(|| format!("failed to write {}", target.display()))?;
        checked_out_assets.push(WorkspaceFile {
            path: asset.path.clone(),
            blob_hash: asset.blob_hash.clone(),
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

    let mut stage = StageFile::default_for_branch(&branch);
    stage.base_changeset_id = snapshot.changeset_id;
    save_stage(&stage)?;

    if json_output_enabled() {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ok": true,
                "repo": repo,
                "branch": branch,
                "asset_count": workspace.checked_out_assets.len(),
            }))?
        );
    } else {
        println!(
            "checked out {}@{} to {} ({} assets)",
            repo,
            branch,
            workspace.workspace_root,
            workspace.checked_out_assets.len()
        );
    }
    Ok(())
}
