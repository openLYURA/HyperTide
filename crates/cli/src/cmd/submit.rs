use anyhow::{anyhow, Context, Result};
use clap::Args;

use crate::utils::*;

#[derive(Debug, Args)]
pub(crate) struct SubmitArgs {
    #[arg(long, help = "Repository id; defaults to the login profile repository")]
    pub repo: Option<String>,
    #[arg(long, help = "Target branch; defaults to the login profile branch")]
    pub branch: Option<String>,
    #[arg(long, default_value = "submit", help = "Submit message")]
    pub message: String,
    #[arg(long)]
    pub visibility: Option<String>,
    #[arg(long)]
    pub from_checkpoint: Option<String>,
}

pub(crate) async fn execute(args: SubmitArgs) -> Result<()> {
    let mut profile = load_profile()?;
    let repo = resolve_repo(&profile, args.repo.as_deref())?;
    let branch = args
        .branch
        .unwrap_or_else(|| profile.current_branch.clone());
    let client = reqwest::Client::new();

    let base_changeset_id = resolve_base_changeset(
        &client,
        &mut profile,
        &repo,
        &branch,
        load_stage()
            .ok()
            .and_then(|s| s.base_changeset_id)
            .as_deref(),
    )
    .await?;

    let author = fetch_owner_id(&client, &profile).await?;

    let stage = load_stage().unwrap_or_else(|_| StageFile::default_for_branch(&branch));
    if stage.assets.is_empty() {
        return Err(anyhow!("nothing staged; use `ht add` first"));
    }

    let session_id = if args.from_checkpoint.is_some() {
        load_session_state().ok().and_then(|s| s.current_session_id)
    } else {
        None
    };

    let visibility_str = args
        .visibility
        .as_deref()
        .or_else(|| args.from_checkpoint.as_ref().map(|_| "draft"));
    let kind = "normal";

    let payload = SubmitRequest {
        repo_id: &repo,
        branch: &branch,
        base_changeset_id: &base_changeset_id,
        kind,
        visibility: visibility_str,
        rollback_of: None,
        author: &author,
        message: &args.message,
        intent_id: None,
        task_id: None,
        agent_run_id: None,
        session_id: session_id.as_deref(),
        parent_checkpoint_id: args.from_checkpoint.as_deref(),
        risk_level: None,
        semantic_summary: None,
        assets: &stage.assets,
    };

    let url = format!("{}/v2/changesets", profile.server.trim_end_matches('/'));
    let response: ApiResponse<ChangesetRecord> = send_authed_api(
        &client,
        &mut profile,
        |client, profile| with_auth(client.post(&url).json(&payload), profile),
        "submit response decode failed",
    )
    .await?;
    if !response.success {
        return Err(anyhow!(submit_error_message(&response)));
    }
    let changeset = response.data.context("missing changeset data")?;
    if json_output_enabled() {
        println!("{}", serde_json::to_string_pretty(&changeset)?);
    } else {
        print_changeset_action("submitted", &changeset);
    }

    let mut updated_stage = StageFile::default_for_branch(&branch);
    updated_stage.base_changeset_id = Some(changeset.changeset_id.clone());
    save_stage(&updated_stage)?;
    Ok(())
}
