use anyhow::Result;
use clap::Args;
use serde::Serialize;

use crate::utils::*;

#[derive(Debug, Args)]
pub(crate) struct DiffArgs {
    #[arg(
        long,
        help = "Repository id; defaults to the workspace or login profile repository"
    )]
    pub repo: Option<String>,
    #[arg(long, help = "Branch to inspect; defaults to the workspace branch")]
    pub branch: Option<String>,
}

pub(crate) async fn execute(args: DiffArgs) -> Result<()> {
    let profile = load_profile()?;
    let workspace = load_workspace()?;
    let _repo =
        resolve_repo(&profile, args.repo.as_deref()).unwrap_or_else(|_| workspace.repo_id.clone());
    let branch = args.branch.unwrap_or_else(|| workspace.branch.clone());
    let stage = load_stage().unwrap_or_else(|_| StageFile::default_for_branch(&branch));

    let rows = collect_asset_rows(&workspace, &stage)?;

    #[derive(Serialize)]
    struct JsonDiffRow {
        path: String,
        base_hash: Option<String>,
        local_hash: Option<String>,
        staged_hash: Option<String>,
        changed: bool,
    }

    if json_output_enabled() {
        let items: Vec<JsonDiffRow> = rows
            .iter()
            .map(|row| {
                let changed = match (&row.base_hash, &row.local_hash) {
                    (Some(base), Some(local)) => base != local,
                    (Some(_), None) => true,
                    (None, Some(_)) => true,
                    _ => false,
                };
                JsonDiffRow {
                    path: row.path.clone(),
                    base_hash: row.base_hash.clone(),
                    local_hash: row.local_hash.clone(),
                    staged_hash: row.staged_hash.clone(),
                    changed: changed || row.staged_hash.is_some(),
                }
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
    } else {
        let mut has_diff = false;
        for row in &rows {
            let changed = match (&row.base_hash, &row.local_hash) {
                (Some(base), Some(local)) => base != local,
                (Some(_), None) => true,
                (None, Some(_)) => true,
                _ => false,
            };
            let staged = row.staged_hash.is_some();
            if changed || staged {
                has_diff = true;
                let base = row.base_hash.as_deref().unwrap_or("<none>");
                let local = row.local_hash.as_deref().unwrap_or("<none>");
                let staged_str = row.staged_hash.as_deref().unwrap_or("<not staged>");
                println!(
                    "{}\n  base:   {}\n  local:  {}\n  staged: {}",
                    row.path, base, local, staged_str
                );
            }
        }
        if !has_diff {
            println!("no differences");
        }
    }
    Ok(())
}
