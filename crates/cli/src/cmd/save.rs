use anyhow::Result;
use clap::Args;

use crate::utils::*;

#[derive(Debug, Args)]
pub(crate) struct SaveArgs {
    #[arg(long)]
    pub repo: Option<String>,
    #[arg(long)]
    pub branch: Option<String>,
    #[arg(long)]
    pub session: Option<String>,
    #[arg(long)]
    pub message: Option<String>,
}

pub(crate) async fn execute(args: SaveArgs) -> Result<()> {
    let mut profile = load_profile()?;
    let repo = resolve_repo(&profile, args.repo.as_deref())?;
    let branch = args
        .branch
        .unwrap_or_else(|| profile.current_branch.clone());
    let client = reqwest::Client::new();
    let session_id = ensure_session(
        &client,
        &mut profile,
        &repo,
        &branch,
        args.session.as_deref(),
        args.message.as_deref(),
    )
    .await?;
    let assets = collect_checkpoint_assets(&client, &mut profile, &branch).await?;
    let checkpoint = create_remote_checkpoint(
        &client,
        &mut profile,
        &session_id,
        "agent_save",
        args.message.as_deref(),
        &assets,
        true,
    )
    .await?;
    save_session_state(&SessionState {
        current_session_id: Some(session_id),
    })?;
    if json_output_enabled() {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ok": true,
                "checkpoint_id": checkpoint.checkpoint_id,
                "session_id": checkpoint.session_id,
                "asset_count": checkpoint.assets.len(),
            }))?
        );
    } else {
        println!(
            "save done: checkpoint_id={} session_id={} asset_count={}",
            checkpoint.checkpoint_id,
            checkpoint.session_id.as_deref().unwrap_or("<none>"),
            checkpoint.assets.len()
        );
    }
    Ok(())
}
