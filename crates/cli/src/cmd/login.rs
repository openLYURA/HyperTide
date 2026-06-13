use anyhow::Result;
use clap::Args;

use crate::utils::*;

#[derive(Debug, Args)]
pub(crate) struct LoginArgs {
    #[arg(long, help = "HyperTide server URL")]
    pub server: String,
    #[arg(long, help = "API key or development token")]
    pub token: String,
    #[arg(
        long,
        default_value_t = false,
        help = "Send the token directly as an API key instead of exchanging it for JWT tokens"
    )]
    pub api_key_direct: bool,
    #[arg(long, help = "Default repository for later commands")]
    pub repo: Option<String>,
    #[arg(
        long,
        default_value = "main",
        help = "Default branch for later commands"
    )]
    pub branch: String,
}

pub(crate) async fn execute(args: LoginArgs) -> Result<()> {
    let mut profile = CliProfile {
        server: args.server,
        api_key: args.token,
        api_key_direct: args.api_key_direct,
        access_token: None,
        refresh_token: None,
        access_token_expires_at: None,
        current_repo: args.repo,
        current_branch: args.branch,
    };

    if !profile.api_key_direct {
        let client = reqwest::Client::new();
        exchange_api_key_for_tokens(&client, &mut profile).await?;
    }

    save_profile(&profile)?;
    if json_output_enabled() {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "ok": true,
            "server": profile.server,
            "branch": profile.current_branch,
            "mode": if profile.api_key_direct { "api-key-direct" } else { "jwt" },
        }))?);
    } else {
        println!(
            "login saved: server={}, branch={}, mode={}",
            profile.server,
            profile.current_branch,
            if profile.api_key_direct {
                "api-key-direct"
            } else {
                "jwt"
            }
        );
    }
    Ok(())
}
