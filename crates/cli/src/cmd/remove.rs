use anyhow::Result;
use clap::Args;

use crate::utils::*;

#[derive(Debug, Args)]
pub(crate) struct RemoveArgs {
    #[arg(long = "asset-path", help = "Repository asset path to remove")]
    pub asset_path: String,
    #[arg(long, help = "Target branch; defaults to the login profile branch")]
    pub branch: Option<String>,
}

pub(crate) async fn execute(args: RemoveArgs) -> Result<()> {
    let profile = load_profile()?;
    let branch = args
        .branch
        .unwrap_or_else(|| profile.current_branch.clone());
    let mut stage = load_stage().unwrap_or_else(|_| StageFile::default_for_branch(&branch));
    if stage.branch != branch {
        stage = StageFile::default_for_branch(&branch);
    }
    upsert_stage_asset(&mut stage, &args.asset_path, None);
    save_stage(&stage)?;
    if json_output_enabled() {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "ok": true,
            "asset_path": args.asset_path,
            "branch": stage.branch,
            "staged_count": stage.assets.len(),
        }))?);
    } else {
        println!(
            "staged delete for {} on {} ({} asset(s) staged)",
            args.asset_path,
            stage.branch,
            stage.assets.len()
        );
    }
    Ok(())
}
