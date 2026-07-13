use std::{collections::HashSet, fs, path::Path};

use anyhow::{anyhow, Context, Result};
use clap::Args;

use crate::utils::*;

#[derive(Debug, Args)]
pub(crate) struct CheckoutArgs {
    #[arg(long, help = "Repository id; defaults to the login profile repository")]
    pub repo: Option<String>,
    #[arg(
        long,
        help = "Branch to checkout; defaults to the login profile branch"
    )]
    pub branch: Option<String>,
    #[arg(long = "to", help = "Optional changeset id to checkout")]
    pub to_changeset_id: Option<String>,
    #[arg(long, help = "Force checkout, overwriting local modifications")]
    pub force: bool,
    #[arg(long, help = "Preview checkout changes without writing files")]
    pub dry_run: bool,
}

pub(crate) async fn execute(args: CheckoutArgs) -> Result<()> {
    let mut profile = load_profile()?;
    let repo = resolve_repo(&profile, args.repo.as_deref())?;
    let branch = args
        .branch
        .unwrap_or_else(|| profile.current_branch.clone());
    let workspace_root = std::env::current_dir()?;

    // Pre-check: detect local modifications before overwriting
    let existing_workspace = load_workspace().ok();
    let matching_workspace = existing_workspace.as_ref().filter(|workspace| {
        workspace.repo_id == repo && Path::new(&workspace.workspace_root) == workspace_root
    });
    if !args.force {
        if let Ok(stage) = load_stage() {
            if !stage.assets.is_empty() {
                return Err(anyhow!(
                    "workspace has {} staged change(s); submit them or use --force",
                    stage.assets.len()
                ));
            }
        }
        if let Some(workspace) = matching_workspace {
            let conflicts = detect_local_modifications(workspace)?;
            if !conflicts.is_empty() {
                eprintln!(
                    "error: workspace has {} uncommitted modification(s), checkout would overwrite:",
                    conflicts.len()
                );
                for c in &conflicts {
                    eprintln!("  {}", c.path);
                }
                eprintln!(
                    "use 'ht add --file <path>' to stage changes, or use '--force' to overwrite."
                );
                return Err(anyhow!("checkout refused to overwrite local changes"));
            }
        }
    }

    let client = reqwest::Client::new();
    let snapshot = fetch_snapshot(
        &client,
        &mut profile,
        &repo,
        &branch,
        args.to_changeset_id.as_deref(),
    )
    .await?;
    validate_snapshot_layout(snapshot.assets.iter().map(|asset| asset.path.as_str()))?;
    if args.dry_run {
        println!(
            "checkout preview {}@{} to {} ({} assets)",
            repo,
            branch,
            snapshot
                .changeset_id
                .clone()
                .unwrap_or_else(|| "ROOT".to_string()),
            snapshot.assets.len()
        );
        for asset in &snapshot.assets {
            println!("  write {} <- {}", asset.path, asset.blob_hash);
        }
        return Ok(());
    }
    let mut checked_out_assets = Vec::with_capacity(snapshot.assets.len());
    let snapshot_paths = snapshot
        .assets
        .iter()
        .map(|asset| asset.path.as_str())
        .collect::<HashSet<_>>();

    if !args.force {
        let tracked_paths = matching_workspace
            .map(|workspace| {
                workspace
                    .checked_out_assets
                    .iter()
                    .map(|asset| asset.path.as_str())
                    .collect::<std::collections::HashSet<_>>()
            })
            .unwrap_or_default();
        let stale_paths = matching_workspace
            .map(|workspace| {
                workspace
                    .checked_out_assets
                    .iter()
                    .filter(|asset| !snapshot_paths.contains(asset.path.as_str()))
                    .map(|asset| asset.path.as_str())
                    .collect::<HashSet<_>>()
            })
            .unwrap_or_default();
        for asset in &snapshot.assets {
            if tracked_paths.contains(asset.path.as_str()) {
                continue;
            }
            let target = resolve_workspace_target(&workspace_root, &asset.path)?;
            if target.is_dir()
                && directory_contains_only_stale_assets(&workspace_root, &target, &stale_paths)?
            {
                continue;
            }
            if target.exists()
                && (target.is_dir()
                    || hash_local_asset(&workspace_root, &asset.path)?.as_deref()
                        != Some(asset.blob_hash.as_str()))
            {
                return Err(anyhow!(
                    "checkout would overwrite untracked local file {}; use --force",
                    asset.path
                ));
            }
        }
    }

    for asset in &snapshot.assets {
        fetch_blob_bytes(&client, &mut profile, &asset.blob_hash).await?;
    }

    if let Some(previous) = matching_workspace {
        remove_stale_tracked_files(&workspace_root, previous, &snapshot_paths)?;
    }

    for asset in &snapshot.assets {
        let target = resolve_workspace_target(&workspace_root, &asset.path)?;
        let bytes = fetch_blob_bytes(&client, &mut profile, &asset.blob_hash).await?;
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&target, &bytes)
            .with_context(|| format!("failed to write {}", target.display()))?;
        checked_out_assets.push(WorkspaceFile {
            path: asset.path.clone(),
            blob_hash: asset.blob_hash.clone(),
            asset_id: asset.asset_id.clone(),
        });
    }

    let workspace = WorkspaceState {
        repo_id: repo.clone(),
        branch: branch.clone(),
        workspace_root: workspace_root.to_string_lossy().to_string(),
        base_changeset_id: snapshot.changeset_id.clone(),
        checked_out_assets,
        last_synced_at: now_unix(),
    };
    save_workspace(&workspace)?;

    let mut stage = StageFile::default_for_branch(&branch);
    stage.base_changeset_id = snapshot.changeset_id;
    save_stage(&stage)?;

    println!(
        "checked out {}@{} to {} ({} assets)",
        repo,
        branch,
        workspace.workspace_root,
        workspace.checked_out_assets.len()
    );
    Ok(())
}

fn validate_snapshot_layout<'a>(paths: impl IntoIterator<Item = &'a str>) -> Result<()> {
    let mut normalized_paths = HashSet::new();
    for path in paths {
        let normalized = path.replace('\\', "/");
        if !normalized_paths.insert(normalized.clone()) {
            return Err(anyhow!("snapshot contains duplicate asset path: {path}"));
        }
    }
    for path in &normalized_paths {
        for (index, byte) in path.bytes().enumerate() {
            if byte == b'/' && normalized_paths.contains(&path[..index]) {
                return Err(anyhow!(
                    "snapshot asset paths conflict: {} and {}",
                    &path[..index],
                    path
                ));
            }
        }
    }
    Ok(())
}

fn directory_contains_only_stale_assets(
    workspace_root: &Path,
    directory: &Path,
    stale_paths: &HashSet<&str>,
) -> Result<bool> {
    let mut contains_stale_asset = false;
    for entry in fs::read_dir(directory)
        .with_context(|| format!("failed to inspect directory {}", directory.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to inspect {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Ok(false);
        }
        if metadata.is_dir() {
            if !directory_contains_only_stale_assets(workspace_root, &path, stale_paths)? {
                return Ok(false);
            }
            contains_stale_asset = true;
            continue;
        }
        if !metadata.is_file() {
            return Ok(false);
        }
        let relative = path
            .strip_prefix(workspace_root)
            .with_context(|| format!("path escapes workspace: {}", path.display()))?;
        let asset_path = normalize_asset_path(relative);
        if !stale_paths.contains(asset_path.as_str()) {
            return Ok(false);
        }
        contains_stale_asset = true;
    }
    Ok(contains_stale_asset)
}

fn remove_stale_tracked_files(
    workspace_root: &Path,
    previous: &WorkspaceState,
    snapshot_paths: &HashSet<&str>,
) -> Result<()> {
    let mut stale_targets = previous
        .checked_out_assets
        .iter()
        .filter(|asset| !snapshot_paths.contains(asset.path.as_str()))
        .map(|asset| resolve_workspace_target(workspace_root, &asset.path))
        .collect::<Result<Vec<_>>>()?;
    stale_targets.sort_by_key(|path| std::cmp::Reverse(path.components().count()));

    for target in stale_targets {
        match fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.is_file() => {
                fs::remove_file(&target)
                    .with_context(|| format!("failed to delete {}", target.display()))?;
                remove_empty_parent_dirs(workspace_root, target.parent())?;
            }
            Ok(_) => {
                return Err(anyhow!(
                    "tracked asset path is not a regular file: {}",
                    target.display()
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect {}", target.display()));
            }
        }
    }
    Ok(())
}

fn remove_empty_parent_dirs(workspace_root: &Path, mut parent: Option<&Path>) -> Result<()> {
    while let Some(directory) = parent.filter(|directory| *directory != workspace_root) {
        match fs::remove_dir(directory) {
            Ok(()) => parent = directory.parent(),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::DirectoryNotEmpty | std::io::ErrorKind::NotFound
                ) =>
            {
                break;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to remove empty directory {}", directory.display())
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace(root: &Path, paths: &[&str]) -> WorkspaceState {
        WorkspaceState {
            repo_id: "repo-a".to_string(),
            branch: "main".to_string(),
            workspace_root: root.to_string_lossy().to_string(),
            base_changeset_id: Some("cs-old".to_string()),
            checked_out_assets: paths
                .iter()
                .map(|path| WorkspaceFile {
                    path: (*path).to_string(),
                    blob_hash: "0".repeat(64),
                    asset_id: None,
                })
                .collect(),
            last_synced_at: 1,
        }
    }

    fn temp_workspace(label: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "hypertide-checkout-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("create test workspace");
        root
    }

    #[test]
    fn stale_file_can_be_replaced_by_a_directory_tree() {
        let root = temp_workspace("file-to-dir");
        fs::write(root.join("Content"), b"old").expect("write old file");
        let previous = workspace(&root, &["Content"]);
        let snapshot_paths = HashSet::from(["Content/A.uasset"]);

        remove_stale_tracked_files(&root, &previous, &snapshot_paths).expect("remove stale file");
        fs::create_dir_all(root.join("Content")).expect("create replacement directory");
        fs::write(root.join("Content/A.uasset"), b"new").expect("write replacement file");

        assert!(root.join("Content/A.uasset").is_file());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn stale_directory_tree_can_be_replaced_by_a_file() {
        let root = temp_workspace("dir-to-file");
        fs::create_dir_all(root.join("Content")).expect("create old directory");
        fs::write(root.join("Content/A.uasset"), b"old").expect("write old file");
        let previous = workspace(&root, &["Content/A.uasset"]);
        let snapshot_paths = HashSet::from(["Content"]);
        let stale_paths = HashSet::from(["Content/A.uasset"]);

        assert!(
            directory_contains_only_stale_assets(&root, &root.join("Content"), &stale_paths)
                .expect("inspect old directory")
        );
        remove_stale_tracked_files(&root, &previous, &snapshot_paths).expect("remove stale tree");
        fs::write(root.join("Content"), b"new").expect("write replacement file");

        assert!(root.join("Content").is_file());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn untracked_files_block_directory_replacement() {
        let root = temp_workspace("untracked-directory-entry");
        fs::create_dir_all(root.join("Content")).expect("create old directory");
        fs::write(root.join("Content/A.uasset"), b"tracked").expect("write tracked file");
        fs::write(root.join("Content/notes.txt"), b"untracked").expect("write untracked file");
        let stale_paths = HashSet::from(["Content/A.uasset"]);

        assert!(
            !directory_contains_only_stale_assets(&root, &root.join("Content"), &stale_paths,)
                .expect("inspect mixed directory")
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn untracked_empty_directories_block_directory_replacement() {
        let root = temp_workspace("untracked-empty-directory");
        fs::create_dir_all(root.join("Content/empty")).expect("create empty directory");
        fs::write(root.join("Content/A.uasset"), b"tracked").expect("write tracked file");
        let stale_paths = HashSet::from(["Content/A.uasset"]);

        assert!(
            !directory_contains_only_stale_assets(&root, &root.join("Content"), &stale_paths)
                .expect("inspect directory with empty subtree")
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn snapshot_layout_rejects_duplicate_and_parent_asset_paths() {
        assert!(validate_snapshot_layout(["Content/A", "Content/A"]).is_err());
        assert!(validate_snapshot_layout(["Content", "Content/A"]).is_err());
        assert!(validate_snapshot_layout(["Content\\A", "Content/A"]).is_err());
        assert!(validate_snapshot_layout(["Content/A", "Content/B"]).is_ok());
    }
}
