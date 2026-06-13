use anyhow::{anyhow, Context, Result};
use clap::{Args, Subcommand};

use crate::utils::*;

#[derive(Debug, Args)]
pub(crate) struct ChangesetArgs {
    #[command(subcommand)]
    pub command: ChangesetCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ChangesetCommand {
    Approve(ChangesetActionArgs),
    Promote(ChangesetPromoteArgs),
    Gate(ChangesetActionArgs),
}

#[derive(Debug, Args)]
pub(crate) struct ChangesetActionArgs {
    #[arg(long, help = "Repository id; defaults to the login profile repository")]
    pub repo: Option<String>,
    #[arg(long, help = "Changeset id")]
    pub id: String,
}

#[derive(Debug, Args)]
pub(crate) struct ChangesetPromoteArgs {
    #[arg(long, help = "Repository id; defaults to the login profile repository")]
    pub repo: Option<String>,
    #[arg(long, help = "Changeset id")]
    pub id: String,
    #[arg(
        long,
        help = "High-risk signing secret; falls back to HT_HIGH_RISK_SIGNING_SECRET"
    )]
    pub high_risk_secret: Option<String>,
    #[arg(long, help = "Skip confirmation prompt")]
    pub yes: bool,
}

pub(crate) async fn execute(args: ChangesetArgs) -> Result<()> {
    match args.command {
        ChangesetCommand::Approve(cmd) => changeset_approve(cmd).await,
        ChangesetCommand::Promote(cmd) => changeset_promote(cmd).await,
        ChangesetCommand::Gate(cmd) => changeset_gate(cmd).await,
    }
}

async fn changeset_approve(args: ChangesetActionArgs) -> Result<()> {
    let mut profile = load_profile()?;
    let repo = resolve_repo(&profile, args.repo.as_deref())?;
    let client = reqwest::Client::new();
    let actor_id = fetch_owner_id(&client, &profile).await?;
    let mut path = format!("/v2/changesets/{}/approve", args.id);
    let mut sep = '?';
    push_query_param(&mut path, &mut sep, "repo_id", Some(&repo));
    let url = format!("{}{}", profile.server.trim_end_matches('/'), path);
    let response: ApiResponse<ChangesetRecord> = send_authed_api(
        &client,
        &mut profile,
        |client, profile| with_auth(client.post(&url), profile),
        "approve response decode failed",
    )
    .await?;
    if !response.success {
        return Err(anyhow!(api_error_message(&response, "approve failed")));
    }
    let changeset = response.data.context("missing changeset data")?;
    if json_output_enabled() {
        println!("{}", serde_json::to_string_pretty(&changeset)?);
    } else {
        print_changeset_action("approved", &changeset);
    }
    let _ = actor_id;
    Ok(())
}

async fn changeset_promote(args: ChangesetPromoteArgs) -> Result<()> {
    confirm_dangerous(
        &format!("promote changeset {} to visible head", args.id),
        args.yes,
    )?;
    let mut profile = load_profile()?;
    let repo = resolve_repo(&profile, args.repo.as_deref())?;
    let client = reqwest::Client::new();
    let actor_id = fetch_owner_id(&client, &profile).await?;
    let payload = serde_json::json!({
        "repo_id": repo,
        "changeset_id": args.id,
    });
    let high_risk = build_high_risk_headers(
        args.high_risk_secret.as_deref(),
        "CHANGESET_PROMOTE",
        &actor_id,
        &payload,
    );
    let mut path = format!("/v2/changesets/{}/promote", args.id);
    let mut sep = '?';
    push_query_param(&mut path, &mut sep, "repo_id", Some(&repo));
    let url = format!("{}{}", profile.server.trim_end_matches('/'), path);
    let response: ApiResponse<ChangesetRecord> = send_authed_api(
        &client,
        &mut profile,
        |client, profile| {
            let req = with_auth(client.post(&url), profile);
            apply_high_risk_headers(req, high_risk.as_ref())
        },
        "promote response decode failed",
    )
    .await?;
    if !response.success {
        return Err(anyhow!(api_error_message(&response, "promote failed")));
    }
    let changeset = response.data.context("missing changeset data")?;
    if json_output_enabled() {
        println!("{}", serde_json::to_string_pretty(&changeset)?);
    } else {
        print_changeset_action("promoted", &changeset);
    }
    Ok(())
}

async fn changeset_gate(args: ChangesetActionArgs) -> Result<()> {
    let mut profile = load_profile()?;
    let repo = resolve_repo(&profile, args.repo.as_deref())?;
    let client = reqwest::Client::new();
    let mut path = format!("/v2/changesets/{}/gate", args.id);
    let mut sep = '?';
    push_query_param(&mut path, &mut sep, "repo_id", Some(&repo));
    let url = format!("{}{}", profile.server.trim_end_matches('/'), path);
    let response: ApiResponse<ChangesetGate> = send_authed_api(
        &client,
        &mut profile,
        |client, profile| with_auth(client.get(&url), profile),
        "gate response decode failed",
    )
    .await?;
    if !response.success {
        return Err(anyhow!(api_error_message(&response, "gate failed")));
    }
    let gate = response.data.context("missing gate data")?;
    if json_output_enabled() {
        println!("{}", serde_json::to_string_pretty(&gate)?);
    } else {
        println!(
            "changeset gate: {} status={} required_state={} can_promote={} blocking_reason={}",
            gate.changeset_id,
            gate.status,
            gate.required_state,
            gate.can_promote,
            gate.blocking_reason.as_deref().unwrap_or("<none>")
        );
    }
    Ok(())
}
