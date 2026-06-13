use anyhow::Result;
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
}

pub(crate) async fn execute(args: SyncArgs) -> Result<()> {
    let mut profile = load_profile()?;
    let repo = resolve_repo(&profile, args.repo.as_deref())?;
    let branch = args
        .branch
        .unwrap_or_else(|| profile.current_branch.clone());
    let client = reqwest::Client::new();
    let snapshot = fetch_snapshot(
        &client,
        &mut profile,
        &repo,
        &branch,
        args.to_changeset_id.as_deref(),
    )
    .await?;

    // Preserve existing stage assets — only update base_changeset_id
    let mut stage = load_stage().unwrap_or_else(|_| StageFile::default_for_branch(&branch));
    stage.base_changeset_id = snapshot.changeset_id;
    save_stage(&stage)?;
    if let Ok(mut workspace) = load_workspace() {
        if workspace.repo_id == repo && workspace.branch == branch {
            workspace.base_changeset_id = stage.base_changeset_id.clone();
            workspace.last_synced_at = now_unix();
            save_workspace(&workspace)?;
        }
    }
    if json_output_enabled() {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "ok": true,
            "repo": repo,
            "branch": branch,
            "changeset_id": stage.base_changeset_id,
            "asset_count": snapshot.assets.len(),
        }))?);
    } else {
        println!(
            "synced {}@{} to {} ({} assets)",
            repo,
            branch,
            stage
                .base_changeset_id
                .clone()
                .unwrap_or_else(|| "ROOT".to_string()),
            snapshot.assets.len()
        );
    }
    Ok(())
}
