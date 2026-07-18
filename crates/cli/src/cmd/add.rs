use std::path::Path;

use anyhow::{anyhow, Result};
use clap::{ArgGroup, Args};

use crate::utils::*;

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("input").required(true).args(["file", "blob"])))]
pub(crate) struct AddArgs {
    #[arg(long = "asset-path", help = "Repository asset path (repo-side name)")]
    pub asset_path: Option<String>,
    #[arg(
        long,
        help = "Existing blob hash to stage",
        requires = "asset_path",
        conflicts_with = "file"
    )]
    pub blob: Option<String>,
    #[arg(
        long,
        help = "Local file to upload and stage (auto-selects direct or chunk upload)",
        conflicts_with = "blob"
    )]
    pub file: Option<String>,
    #[arg(long, help = "Target branch; defaults to the login profile branch")]
    pub branch: Option<String>,
}

pub(crate) async fn execute(args: AddArgs) -> Result<()> {
    let profile = load_profile()?;
    let branch = args
        .branch
        .unwrap_or_else(|| profile.current_branch.clone());

    match (args.file, args.asset_path, args.blob) {
        (Some(file), None, None) => add_file(Path::new(&file), None, &branch).await,
        (Some(file), Some(path), None) => add_file(Path::new(&file), Some(&path), &branch).await,
        (None, Some(path), Some(blob)) => {
            let mut stage = load_stage().unwrap_or_else(|_| StageFile::default_for_branch(&branch));
            if stage.branch != branch {
                stage = StageFile::default_for_branch(&branch);
            }
            let asset_id = load_workspace().ok().and_then(|workspace| {
                (workspace.branch == branch)
                    .then_some(workspace.checked_out_assets)
                    .into_iter()
                    .flatten()
                    .find(|asset| asset.path == path)
                    .and_then(|asset| asset.asset_id)
            });
            upsert_stage_asset(&mut stage, &path, Some(blob), asset_id);
            save_stage(&stage)?;
            println!("staged {} asset(s) on {}", stage.assets.len(), stage.branch);
            Ok(())
        }
        _ => Err(anyhow!(
            "use either `ht add --file <local-file> [--asset-path <repo-path>]` or `ht add --blob <hash> --asset-path <repo-path>`"
        )),
    }
}
