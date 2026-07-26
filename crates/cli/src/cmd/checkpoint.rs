use anyhow::{anyhow, Context, Result};
use clap::{Args, Subcommand};

use crate::utils::*;

#[derive(Debug, Args)]
pub(crate) struct CheckpointArgs {
    #[command(subcommand)]
    pub command: CheckpointCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum CheckpointCommand {
    #[command(about = "Create a recoverable workspace checkpoint")]
    Create(CheckpointCreateArgs),
    #[command(about = "Restore workspace to a checkpoint")]
    Restore(CheckpointRestoreArgs),
    #[command(about = "Create a branch from a checkpoint")]
    Branch(CheckpointBranchArgs),
    #[command(about = "List checkpoints for the current session")]
    List(CheckpointListArgs),
}

#[derive(Debug, Args)]
pub(crate) struct CheckpointCreateArgs {
    #[arg(long)]
    pub repo: Option<String>,
    #[arg(long)]
    pub branch: Option<String>,
    #[arg(long)]
    pub session: Option<String>,
    #[arg(long)]
    pub message: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct CheckpointRestoreArgs {
    #[arg(long)]
    pub id: String,
    #[arg(long, help = "Force restore, overwriting local modifications")]
    pub force: bool,
}

#[derive(Debug, Args)]
pub(crate) struct CheckpointBranchArgs {
    #[arg(long)]
    pub id: String,
    #[arg(long)]
    pub name: String,
    #[arg(long, help = "Force materialization, overwriting local modifications")]
    pub force: bool,
}

#[derive(Debug, Args)]
pub(crate) struct CheckpointListArgs {
    #[arg(long)]
    pub session: Option<String>,
}

pub(crate) async fn execute(args: CheckpointArgs) -> Result<()> {
    match args.command {
        CheckpointCommand::Create(cmd) => checkpoint_create(cmd).await,
        CheckpointCommand::Restore(cmd) => checkpoint_restore(cmd).await,
        CheckpointCommand::Branch(cmd) => checkpoint_branch(cmd).await,
        CheckpointCommand::List(cmd) => checkpoint_list(cmd).await,
    }
}

async fn checkpoint_create(args: CheckpointCreateArgs) -> Result<()> {
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
        "agent_checkpoint",
        args.message.as_deref(),
        &assets,
        false,
    )
    .await?;
    save_session_state(&SessionState {
        current_session_id: Some(session_id),
    })?;
    println!(
        "checkpoint created: checkpoint_id={} session_id={} asset_count={}",
        checkpoint.checkpoint_id,
        checkpoint.session_id.as_deref().unwrap_or("<none>"),
        checkpoint.assets.len()
    );
    Ok(())
}

async fn checkpoint_restore(args: CheckpointRestoreArgs) -> Result<()> {
    let mut profile = load_profile()?;
    let client = reqwest::Client::new();
    let snapshot = fetch_checkpoint_snapshot(&client, &mut profile, &args.id).await?;
    materialize_checkpoint_snapshot(&client, &mut profile, &snapshot, args.force).await?;
    println!(
        "checkpoint restored: checkpoint_id={} session_id={} repo_id={} branch={} asset_count={}",
        snapshot.checkpoint_id,
        snapshot.session_id,
        snapshot.repo_id,
        snapshot.branch,
        snapshot.assets.len()
    );
    Ok(())
}

async fn checkpoint_branch(args: CheckpointBranchArgs) -> Result<()> {
    let mut profile = load_profile()?;
    let client = reqwest::Client::new();
    let snapshot = fetch_checkpoint_snapshot(&client, &mut profile, &args.id).await?;
    let payload = CreateBranchRequest {
        repo_id: &snapshot.repo_id,
        branch: &args.name,
        from_changeset_id: snapshot.base_changeset_id.as_deref(),
    };
    let url = format!("{}/v2/branches", profile.server.trim_end_matches('/'));
    let response: ApiResponse<BranchRecord> = send_authed_api(
        &client,
        &mut profile,
        |client, profile| with_auth(client.post(&url).json(&payload), profile),
        "create branch response decode failed",
    )
    .await?;
    if !response.success {
        return Err(anyhow!(api_error_message(
            &response,
            "create branch failed"
        )));
    }
    materialize_checkpoint_snapshot(&client, &mut profile, &snapshot, args.force).await?;
    profile.current_repo = Some(snapshot.repo_id.clone());
    profile.current_branch = args.name.clone();
    save_profile(&profile)?;

    let mut stage = StageFile::default_for_branch(&args.name);
    stage.base_changeset_id = snapshot.base_changeset_id.clone();
    save_stage(&stage)?;
    println!(
        "branched from checkpoint: checkpoint_id={} branch={} asset_count={}",
        args.id,
        args.name,
        snapshot.assets.len()
    );
    Ok(())
}

async fn checkpoint_list(args: CheckpointListArgs) -> Result<()> {
    let mut profile = load_profile()?;
    let client = reqwest::Client::new();
    let session_id = if let Some(sid) = args.session {
        sid
    } else if let Ok(state) = load_session_state() {
        state
            .current_session_id
            .ok_or_else(|| anyhow!("no active session; pass --session"))?
    } else {
        return Err(anyhow!("no active session; pass --session"));
    };
    let url = format!(
        "{}/v2/sessions/{}/checkpoints",
        profile.server.trim_end_matches('/'),
        session_id
    );
    let response: ApiResponse<CheckpointPage> = send_authed_api(
        &client,
        &mut profile,
        |client, profile| with_auth(client.get(&url), profile),
        "list checkpoints response decode failed",
    )
    .await?;
    if !response.success {
        return Err(anyhow!(api_error_message(
            &response,
            "list checkpoints failed"
        )));
    }
    let data = response.data.context("missing response data")?;
    for cp in data.items {
        println!(
            "{}  session={} branch={} trigger={} assets={}",
            cp.checkpoint_id,
            cp.session_id.as_deref().unwrap_or("<none>"),
            cp.branch.as_deref().unwrap_or("<none>"),
            cp.trigger_reason.as_deref().unwrap_or("<none>"),
            cp.assets.len()
        );
    }
    Ok(())
}
