use anyhow::{anyhow, Context, Result};
use clap::{Args, Subcommand};

use crate::utils::*;

#[derive(Debug, Args)]
pub(crate) struct BranchArgs {
    #[command(subcommand)]
    pub command: BranchCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum BranchCommand {
    #[command(about = "Create a branch")]
    Create(BranchCreateArgs),
    #[command(about = "List branches")]
    List(BranchListArgs),
    #[command(about = "Switch the default branch")]
    Switch(BranchSwitchArgs),
}

#[derive(Debug, Args)]
pub(crate) struct BranchCreateArgs {
    #[arg(long, help = "Repository id; defaults to the login profile repository")]
    pub repo: Option<String>,
    #[arg(long, help = "Branch name to create")]
    pub name: String,
    #[arg(long, help = "Source changeset id for the new branch")]
    pub from: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct BranchListArgs {
    #[arg(long, help = "Repository id; defaults to the login profile repository")]
    pub repo: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct BranchSwitchArgs {
    #[arg(long, help = "Repository id; defaults to the login profile repository")]
    pub repo: Option<String>,
    #[arg(long, help = "Branch name to make current")]
    pub name: String,
    #[arg(long, help = "Force switch, clearing staged changes")]
    pub force: bool,
    #[arg(long, help = "Skip confirmation prompt")]
    pub yes: bool,
}

pub(crate) async fn execute(args: BranchArgs) -> Result<()> {
    match args.command {
        BranchCommand::Create(cmd) => branch_create(cmd).await,
        BranchCommand::List(cmd) => branch_list(cmd).await,
        BranchCommand::Switch(cmd) => branch_switch(cmd).await,
    }
}

async fn branch_create(args: BranchCreateArgs) -> Result<()> {
    let mut profile = load_profile()?;
    let repo = resolve_repo(&profile, args.repo.as_deref())?;
    let client = reqwest::Client::new();
    let payload = CreateBranchRequest {
        repo_id: &repo,
        branch: &args.name,
        from_changeset_id: args.from.as_deref(),
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
    if json_output_enabled() {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "ok": true,
            "branch": args.name,
        }))?);
    } else {
        println!("branch created: {}", args.name);
    }
    Ok(())
}

async fn branch_list(args: BranchListArgs) -> Result<()> {
    let mut profile = load_profile()?;
    let repo = resolve_repo(&profile, args.repo.as_deref())?;
    let client = reqwest::Client::new();
    let url = format!(
        "{}/v2/branches/{}",
        profile.server.trim_end_matches('/'),
        repo
    );
    let response: ApiResponse<BranchListResponse> = send_authed_api(
        &client,
        &mut profile,
        |client, profile| with_auth(client.get(&url), profile),
        "list branches response decode failed",
    )
    .await?;
    if !response.success {
        return Err(anyhow!(api_error_message(
            &response,
            "list branches failed"
        )));
    }
    let data = response.data.context("missing response data")?;
    if json_output_enabled() {
        println!("{}", serde_json::to_string_pretty(&data.branches)?);
    } else {
        for branch in data.branches {
            println!(
                "{}  head={}",
                branch.name,
                branch
                    .head_changeset_id
                    .unwrap_or_else(|| "None".to_string())
            );
        }
    }
    Ok(())
}

async fn branch_switch(args: BranchSwitchArgs) -> Result<()> {
    let mut profile = load_profile()?;
    let repo = resolve_repo(&profile, args.repo.as_deref())?;

    if !args.force {
        if let Ok(stage) = load_stage() {
            if !stage.assets.is_empty() {
                eprintln!(
                    "warning: current branch has {} staged modification(s).",
                    stage.assets.len()
                );
                eprintln!(
                    "switching branches will clear the staging area. use '--force' to force switch."
                );
                eprintln!("or run 'ht submit' first to save your changes.");
                std::process::exit(1);
            }
        }
    } else {
        confirm_dangerous("force branch switch (clears staged changes)", args.yes)?;
    }

    let client = reqwest::Client::new();
    let url = format!(
        "{}/v2/branches/{}",
        profile.server.trim_end_matches('/'),
        repo
    );
    let response: ApiResponse<BranchListResponse> = send_authed_api(
        &client,
        &mut profile,
        |client, profile| with_auth(client.get(&url), profile),
        "switch branch response decode failed",
    )
    .await?;
    if !response.success {
        return Err(anyhow!(api_error_message(
            &response,
            "list branches failed"
        )));
    }
    let data = response.data.context("missing response data")?;
    if !data.branches.iter().any(|b| b.name == args.name) {
        return Err(anyhow!("branch not found: {}", args.name));
    }
    profile.current_repo = Some(repo);
    profile.current_branch = args.name.clone();
    save_profile(&profile)?;

    let mut stage =
        load_stage().unwrap_or_else(|_| StageFile::default_for_branch(&profile.current_branch));
    stage.branch = profile.current_branch.clone();
    stage.base_changeset_id = None;
    stage.assets.clear();
    save_stage(&stage)?;
    if json_output_enabled() {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "ok": true,
            "branch": profile.current_branch,
        }))?);
    } else {
        println!("switched to branch {}", profile.current_branch);
    }
    Ok(())
}
