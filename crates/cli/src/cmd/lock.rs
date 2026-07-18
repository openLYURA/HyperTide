use anyhow::{anyhow, Result};
use clap::{Args, Subcommand};

use crate::utils::*;

#[derive(Debug, Args)]
pub(crate) struct LockArgs {
    #[command(subcommand)]
    pub command: LockCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum LockCommand {
    Acquire(LockPathArgs),
    Release(LockPathArgs),
    Renew(LockPathArgs),
    List,
    ForceRelease(LockForceReleaseArgs),
}

#[derive(Debug, Args)]
pub(crate) struct LockPathArgs {
    #[arg(long, help = "Repository asset path to lock")]
    pub path: String,
}

#[derive(Debug, Args)]
pub(crate) struct LockForceReleaseArgs {
    #[arg(long, help = "Repository asset path to force release")]
    pub path: String,
    #[arg(
        long,
        help = "High-risk signing secret; falls back to HT_HIGH_RISK_SIGNING_SECRET"
    )]
    pub high_risk_secret: Option<String>,
    #[arg(long, help = "Skip confirmation prompt")]
    pub yes: bool,
}

pub(crate) async fn execute(args: LockArgs) -> Result<()> {
    match args.command {
        LockCommand::Acquire(cmd) => lock_acquire(cmd).await,
        LockCommand::Release(cmd) => lock_release(cmd).await,
        LockCommand::Renew(cmd) => lock_renew(cmd).await,
        LockCommand::List => lock_list().await,
        LockCommand::ForceRelease(cmd) => lock_force_release(cmd).await,
    }
}

async fn lock_acquire(args: LockPathArgs) -> Result<()> {
    let lock = send_lock_path_request("lock acquire", "acquire", &args.path, None).await?;
    print_lock("lock acquired", &lock);
    Ok(())
}

async fn lock_release(args: LockPathArgs) -> Result<()> {
    let lock = send_lock_path_request("lock release", "release", &args.path, None).await?;
    print_lock("lock released", &lock);
    Ok(())
}

async fn lock_renew(args: LockPathArgs) -> Result<()> {
    let lock = send_lock_path_request("lock renew", "renew", &args.path, None).await?;
    print_lock("lock renewed", &lock);
    Ok(())
}

async fn lock_list() -> Result<()> {
    let mut profile = load_profile()?;
    let client = reqwest::Client::new();
    let repo_id = resolve_repo(&profile, None)?;
    let locks = fetch_locks(&client, &mut profile, &repo_id).await?;
    if locks.is_empty() {
        println!("no active locks");
    } else {
        for lock in &locks {
            print_lock("lock", lock);
        }
    }
    Ok(())
}

async fn lock_force_release(args: LockForceReleaseArgs) -> Result<()> {
    confirm_dangerous(&format!("force release lock on {}", args.path), args.yes)?;
    let mut profile = load_profile()?;
    let client = reqwest::Client::new();
    let repo_id = resolve_repo(&profile, None)?;
    let payload = LockRequest {
        file_path: &args.path,
        repo_id: &repo_id,
        scope: "asset",
    };
    let high_risk_payload = serde_json::json!({
        "file_path": args.path,
        "repo_id": &repo_id,
        "scope": "asset",
    });
    let high_risk = build_high_risk_headers(
        args.high_risk_secret.as_deref(),
        "LOCK_FORCE_RELEASE",
        "system-admin",
        &high_risk_payload,
    );
    let url = format!(
        "{}/v2/locks/force-release",
        profile.server.trim_end_matches('/')
    );
    let response: ApiResponse<bool> = send_authed_api(
        &client,
        &mut profile,
        |client, profile| {
            let req = with_auth(client.post(&url).json(&payload), profile);
            apply_high_risk_headers(req, high_risk.as_ref())
        },
        "force-release response decode failed",
    )
    .await?;
    if !response.success {
        return Err(anyhow!(api_error_message(
            &response,
            "force-release failed"
        )));
    }
    println!("lock force-released: {}", args.path);
    Ok(())
}
