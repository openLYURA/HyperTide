use anyhow::Result;
use clap::Args;
use serde::Serialize;

use crate::utils::*;

#[derive(Debug, Args)]
pub(crate) struct StatusArgs {
    #[arg(
        long,
        help = "Repository id; defaults to the workspace or login profile repository"
    )]
    pub repo: Option<String>,
    #[arg(long, help = "Branch to inspect; defaults to the workspace branch")]
    pub branch: Option<String>,
}

pub(crate) async fn execute(args: StatusArgs) -> Result<()> {
    let mut profile = load_profile()?;
    let workspace = load_workspace()?;
    let repo =
        resolve_repo(&profile, args.repo.as_deref()).unwrap_or_else(|_| workspace.repo_id.clone());
    let branch = args.branch.unwrap_or_else(|| workspace.branch.clone());
    let client = reqwest::Client::new();
    let stage = load_stage().unwrap_or_else(|_| StageFile::default_for_branch(&branch));
    let locks = fetch_locks(&client, &mut profile, &repo)
        .await
        .unwrap_or_default();
    let head = resolve_base_changeset(&client, &mut profile, &repo, &branch, None).await?;
    let stale_base = workspace
        .base_changeset_id
        .as_deref()
        .unwrap_or(ROOT_BASE_CHANGESET_ID)
        != head;

    let rows = collect_asset_rows(&workspace, &stage)?;
    if rows.is_empty() {
        println!("no assets tracked");
        return Ok(());
    }

    let lock_map: std::collections::HashMap<String, String> = locks
        .into_iter()
        .map(|lock| (lock.file_path, lock.owner_id))
        .collect();

    if json_output_enabled() {
        #[derive(Serialize)]
        struct JsonAssetStatus {
            path: String,
            status: String,
            base_hash: Option<String>,
            local_hash: Option<String>,
            staged_hash: Option<String>,
        }
        let items: Vec<JsonAssetStatus> = rows
            .iter()
            .map(|row| {
                let lock_owner = lock_map.get(&row.path).map(|s| s.as_str());
                let status = classify_asset_status(
                    row.base_hash.as_deref(),
                    row.local_hash.as_deref(),
                    row.staged_hash.as_deref(),
                    lock_owner,
                    stale_base,
                );
                JsonAssetStatus {
                    path: row.path.clone(),
                    status: status.as_str().to_string(),
                    base_hash: row.base_hash.clone(),
                    local_hash: row.local_hash.clone(),
                    staged_hash: row.staged_hash.clone(),
                }
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
    } else {
        for row in &rows {
            let lock_owner = lock_map.get(&row.path).map(|s| s.as_str());
            let status = classify_asset_status(
                row.base_hash.as_deref(),
                row.local_hash.as_deref(),
                row.staged_hash.as_deref(),
                lock_owner,
                stale_base,
            );
            println!("{:<12} {}", status.as_str(), row.path);
        }
    }
    Ok(())
}
