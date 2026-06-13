use std::fs;

use anyhow::{anyhow, Context, Result};
use clap::Args;

use crate::utils::*;

#[derive(Debug, Args)]
pub(crate) struct RevertArgs {
    #[arg(long = "asset-path", help = "Repository asset path to revert")]
    pub asset_path: String,
    #[arg(long, help = "Repository id; defaults to the login profile repository")]
    pub repo: Option<String>,
    #[arg(
        long,
        help = "Branch to revert from; defaults to the login profile branch"
    )]
    pub branch: Option<String>,
    #[arg(long = "to", help = "Optional changeset id to revert from")]
    pub to_changeset_id: Option<String>,
    #[arg(long, help = "Skip confirmation prompts")]
    pub yes: bool,
    #[arg(long, help = "Keep the HyperTide lock after reverting")]
    pub keep_lock: bool,
}

pub(crate) async fn execute(args: RevertArgs) -> Result<()> {
    let asset_path = normalize_revert_asset_path(&args.asset_path)?;

    let mut profile = load_profile()?;
    let repo = resolve_repo(&profile, args.repo.as_deref())?;
    let branch = args
        .branch
        .unwrap_or_else(|| profile.current_branch.clone());
    let mut workspace = load_workspace()
        .context("workspace not initialized; run `ht checkout` before reverting assets")?;
    if workspace.repo_id != repo || workspace.branch != branch {
        return Err(anyhow!(
            "workspace is bound to {}@{}, not {}@{}",
            workspace.repo_id,
            workspace.branch,
            repo,
            branch
        ));
    }

    let workspace_root = std::path::PathBuf::from(&workspace.workspace_root);
    let target = resolve_workspace_target(&workspace_root, &asset_path)?;
    let mut stage = load_stage().unwrap_or_else(|_| StageFile::default_for_branch(&branch));
    if stage.branch != branch {
        stage = StageFile::default_for_branch(&branch);
    }

    let has_staged_delta = stage.assets.iter().any(|asset| asset.path == asset_path);
    let base_hash = workspace
        .checked_out_assets
        .iter()
        .find(|asset| asset.path == asset_path)
        .map(|asset| asset.blob_hash.clone());
    let local_hash = hash_local_asset(&workspace_root, &asset_path)?;
    let overwrites_local_change = match (local_hash.as_deref(), base_hash.as_deref()) {
        (Some(local), Some(base)) => local != base,
        (Some(_), None) => true,
        (None, Some(_)) => true, // local file was deleted — restoring it overwrites the user's uncommitted delete
        (None, None) => false,
    };
    if has_staged_delta || overwrites_local_change {
        let mut actions = Vec::new();
        if has_staged_delta {
            actions.push("remove staged delta");
        }
        if overwrites_local_change {
            actions.push("overwrite local file");
        }
        confirm_dangerous(
            &format!("revert {} ({})", asset_path, actions.join(", ")),
            args.yes,
        )?;
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

    let snapshot_asset = find_snapshot_asset(&snapshot, &asset_path);

    let _update = match snapshot_asset {
        Some(asset) => {
            let bytes = fetch_blob_bytes(&client, &mut profile, &asset.blob_hash).await?;
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
            fs::write(&target, &bytes)
                .with_context(|| format!("failed to write {}", target.display()))?;

            let update = apply_revert_state(
                &mut workspace,
                &mut stage,
                &asset_path,
                Some(&asset.blob_hash),
                base_hash.as_deref(),
                asset.asset_id.clone(),
            );

            if !args.keep_lock {
                if let Err(err) =
                    send_lock_path_request("lock release", "release", &asset_path).await
                {
                    eprintln!(
                        "warning: reverted {}, but failed to release lock: {err}",
                        asset_path
                    );
                    eprintln!(
                        "run `ht lock release --path {}` manually if needed",
                        asset_path
                    );
                }
            }

            if json_output_enabled() {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "asset_path": asset_path,
                        "restored_hash": asset.blob_hash,
                    }))?
                );
            } else {
                println!(
                    "reverted {} to {} on {}@{}{}",
                    asset_path,
                    snapshot
                        .changeset_id
                        .as_deref()
                        .unwrap_or(ROOT_BASE_CHANGESET_ID),
                    repo,
                    branch,
                    if update.removed_staged_delta {
                        " (removed staged delta)"
                    } else if update.staged_delta {
                        " (staged delta)"
                    } else {
                        ""
                    }
                );
            }

            update
        }
        None => {
            // Asset not found in target snapshot — stage a deletion
            if target.exists() {
                fs::remove_file(&target)
                    .with_context(|| format!("failed to delete {}", target.display()))?;
            }

            let update = apply_revert_state(
                &mut workspace,
                &mut stage,
                &asset_path,
                None,
                base_hash.as_deref(),
                None,
            );

            if json_output_enabled() {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "asset_path": asset_path,
                        "restored_hash": null,
                        "staged_deletion": true,
                    }))?
                );
            } else {
                println!(
                    "reverted {} to absent on {}@{}{}",
                    asset_path,
                    repo,
                    branch,
                    if update.staged_delta {
                        " (staged deletion)"
                    } else {
                        ""
                    }
                );
            }

            update
        }
    };

    workspace.last_synced_at = now_unix();
    save_workspace(&workspace)?;
    save_stage(&stage)?;
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct RevertStateUpdate {
    removed_staged_delta: bool,
    staged_delta: bool,
}

fn normalize_revert_asset_path(asset_path: &str) -> Result<String> {
    let normalized = asset_path.trim().replace('\\', "/");
    let trimmed = normalized.as_str();
    if trimmed.is_empty() {
        return Err(anyhow!("asset path cannot be empty"));
    }
    if trimmed.ends_with('/') || trimmed.ends_with('\\') {
        return Err(anyhow!("directory revert is not supported: {asset_path}"));
    }
    if trimmed.contains('*') || trimmed.contains('?') {
        return Err(anyhow!("wildcard revert is not supported: {asset_path}"));
    }
    Ok(normalized)
}

fn remove_staged_asset(stage: &mut StageFile, asset_path: &str) -> bool {
    let original_len = stage.assets.len();
    stage.assets.retain(|asset| asset.path != asset_path);
    stage.assets.len() != original_len
}

fn update_workspace_asset(workspace: &mut WorkspaceState, asset_path: &str, blob_hash: &str) {
    if let Some(existing) = workspace
        .checked_out_assets
        .iter_mut()
        .find(|asset| asset.path == asset_path)
    {
        existing.blob_hash = blob_hash.to_string();
        return;
    }

    workspace.checked_out_assets.push(WorkspaceFile {
        path: asset_path.to_string(),
        blob_hash: blob_hash.to_string(),
    });
}

fn apply_revert_state(
    workspace: &mut WorkspaceState,
    stage: &mut StageFile,
    asset_path: &str,
    blob_hash: Option<&str>,
    base_hash: Option<&str>,
    asset_id: Option<String>,
) -> RevertStateUpdate {
    if base_hash == blob_hash {
        if let Some(hash) = blob_hash {
            update_workspace_asset(workspace, asset_path, hash);
        }
        return RevertStateUpdate {
            removed_staged_delta: remove_staged_asset(stage, asset_path),
            staged_delta: false,
        };
    }

    upsert_stage_asset(
        stage,
        asset_path,
        blob_hash.map(|h| h.to_string()),
        asset_id,
    );
    RevertStateUpdate {
        removed_staged_delta: false,
        staged_delta: true,
    }
}

fn find_snapshot_asset<'a>(snapshot: &'a SyncResponse, asset_path: &str) -> Option<&'a SyncAsset> {
    snapshot
        .assets
        .iter()
        .find(|asset| asset.path == asset_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::{
        save_profile, save_stage, save_workspace, AssetDelta, CliProfile, StageFile, StorageHash,
        SyncAsset, SyncResponse, WorkspaceFile, WorkspaceState,
    };
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn cwd_lock() -> &'static tokio::sync::Mutex<()> {
        static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    fn unique_workspace(name: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir()
            .join("hypertide-cli-revert-e2e")
            .join(format!(
                "{}-{}-{}",
                name,
                nanos,
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ))
    }

    fn write_file(path: &Path, bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("parent dir");
        }
        std::fs::write(path, bytes).expect("write file");
    }

    #[derive(Clone)]
    struct FakeResponse {
        status: &'static str,
        content_type: &'static str,
        body: Vec<u8>,
    }

    struct FakeServer {
        base_url: String,
        requests: Arc<Mutex<Vec<String>>>,
        handle: thread::JoinHandle<()>,
    }

    impl FakeServer {
        fn start(responses: Vec<FakeResponse>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake server");
            let base_url = format!("http://{}", listener.local_addr().expect("addr"));
            let requests = Arc::new(Mutex::new(Vec::new()));
            let request_log = Arc::clone(&requests);
            let handle = thread::spawn(move || {
                for response in responses {
                    let (mut stream, _) = listener.accept().expect("accept");
                    let request = read_http_request(&mut stream);
                    request_log.lock().expect("request log").push(request);
                    let header = format!(
                        "HTTP/1.1 {}\r\ncontent-length: {}\r\ncontent-type: {}\r\nconnection: close\r\n\r\n",
                        response.status,
                        response.body.len(),
                        response.content_type
                    );
                    stream.write_all(header.as_bytes()).expect("write header");
                    stream.write_all(&response.body).expect("write body");
                }
            });
            Self {
                base_url,
                requests,
                handle,
            }
        }

        fn finish(self) -> Vec<String> {
            self.handle.join().expect("fake server thread");
            let requests = self.requests.lock().expect("request log");
            requests.clone()
        }
    }

    fn read_http_request(stream: &mut std::net::TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buffer).expect("read request");
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..read]);
            if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                let request = String::from_utf8_lossy(&bytes).to_string();
                let content_length = request
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("content-length:")
                            .or_else(|| line.strip_prefix("Content-Length:"))
                    })
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                let header_len = bytes
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .expect("headers")
                    + 4;
                while bytes.len() < header_len + content_length {
                    let read = stream.read(&mut buffer).expect("read body");
                    if read == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&buffer[..read]);
                }
                break;
            }
        }
        String::from_utf8_lossy(&bytes).to_string()
    }

    fn sync_response(repo: &str, branch: &str, changeset: &str, path: &str, hash: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "success": true,
            "data": {
                "repo_id": repo,
                "branch": branch,
                "changeset_id": changeset,
                "assets": [{
                    "asset_id": path,
                    "path": path,
                    "blob_hash": hash
                }]
            },
            "error": null
        }))
        .expect("sync json")
    }

    fn lock_release_response(path: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "success": true,
            "data": {
                "file_path": path,
                "owner_id": "owner",
                "locked_at": "2026-06-11T00:00:00Z",
                "lease_expires_at": null
            },
            "error": null
        }))
        .expect("lock json")
    }

    fn setup_revert_workspace(
        root: &Path,
        server_url: &str,
        repo: &str,
        branch: &str,
        asset_path: &str,
        base_hash: &str,
        stage_assets: Vec<AssetDelta>,
    ) {
        std::fs::create_dir_all(root).expect("workspace root");
        save_profile(&CliProfile {
            server: server_url.to_string(),
            api_key: "test-key".to_string(),
            api_key_direct: true,
            access_token: None,
            refresh_token: None,
            access_token_expires_at: None,
            current_repo: Some(repo.to_string()),
            current_branch: branch.to_string(),
        })
        .expect("save profile");
        save_workspace(&WorkspaceState {
            repo_id: repo.to_string(),
            branch: branch.to_string(),
            workspace_root: root.to_string_lossy().to_string(),
            base_changeset_id: Some("head-cs".to_string()),
            checked_out_assets: vec![WorkspaceFile {
                path: asset_path.to_string(),
                blob_hash: base_hash.to_string(),
            }],
            last_synced_at: 1,
        })
        .expect("save workspace");
        save_stage(&StageFile {
            branch: branch.to_string(),
            base_changeset_id: Some("head-cs".to_string()),
            assets: stage_assets,
        })
        .expect("save stage");
    }

    #[test]
    fn remove_staged_asset_removes_only_matching_path() {
        let mut stage = StageFile {
            branch: "main".to_string(),
            base_changeset_id: Some("cs-0".to_string()),
            assets: vec![
                AssetDelta {
                    path: "Content/A.uasset".to_string(),
                    blob_hash: Some("hash-a".to_string()),
                    asset_id: None,
                },
                AssetDelta {
                    path: "Content/B.uasset".to_string(),
                    blob_hash: None,
                    asset_id: None,
                },
            ],
        };

        assert!(remove_staged_asset(&mut stage, "Content/A.uasset"));

        assert_eq!(stage.assets.len(), 1);
        assert_eq!(stage.assets[0].path, "Content/B.uasset");
    }

    #[test]
    fn update_workspace_asset_replaces_existing_hash() {
        let mut workspace = WorkspaceState {
            repo_id: "repo".to_string(),
            branch: "main".to_string(),
            workspace_root: ".".to_string(),
            base_changeset_id: Some("cs-0".to_string()),
            checked_out_assets: vec![WorkspaceFile {
                path: "Content/A.uasset".to_string(),
                blob_hash: "old".to_string(),
            }],
            last_synced_at: 1,
        };

        update_workspace_asset(&mut workspace, "Content/A.uasset", "new");

        assert_eq!(workspace.checked_out_assets.len(), 1);
        assert_eq!(workspace.checked_out_assets[0].blob_hash, "new");
    }

    #[test]
    fn update_workspace_asset_inserts_missing_asset() {
        let mut workspace = WorkspaceState {
            repo_id: "repo".to_string(),
            branch: "main".to_string(),
            workspace_root: ".".to_string(),
            base_changeset_id: None,
            checked_out_assets: Vec::new(),
            last_synced_at: 1,
        };

        update_workspace_asset(&mut workspace, "Content/A.uasset", "hash-a");

        assert_eq!(workspace.checked_out_assets.len(), 1);
        assert_eq!(workspace.checked_out_assets[0].path, "Content/A.uasset");
        assert_eq!(workspace.checked_out_assets[0].blob_hash, "hash-a");
    }

    #[test]
    fn apply_revert_state_stages_blob_when_target_differs_from_workspace_base() {
        let mut workspace = WorkspaceState {
            repo_id: "repo".to_string(),
            branch: "main".to_string(),
            workspace_root: ".".to_string(),
            base_changeset_id: Some("cs-head".to_string()),
            checked_out_assets: vec![WorkspaceFile {
                path: "Content/A.uasset".to_string(),
                blob_hash: "head-hash".to_string(),
            }],
            last_synced_at: 1,
        };
        let mut stage = StageFile::default_for_branch("main");

        let update = apply_revert_state(
            &mut workspace,
            &mut stage,
            "Content/A.uasset",
            Some("old-hash"),
            Some("head-hash"),
            None,
        );

        assert_eq!(
            update,
            RevertStateUpdate {
                removed_staged_delta: false,
                staged_delta: true,
            }
        );
        assert_eq!(workspace.checked_out_assets[0].blob_hash, "head-hash");
        assert_eq!(stage.assets.len(), 1);
        assert_eq!(stage.assets[0].path, "Content/A.uasset");
        assert_eq!(stage.assets[0].blob_hash.as_deref(), Some("old-hash"));
    }

    #[test]
    fn apply_revert_state_clears_stage_when_target_matches_workspace_base() {
        let mut workspace = WorkspaceState {
            repo_id: "repo".to_string(),
            branch: "main".to_string(),
            workspace_root: ".".to_string(),
            base_changeset_id: Some("cs-head".to_string()),
            checked_out_assets: vec![WorkspaceFile {
                path: "Content/A.uasset".to_string(),
                blob_hash: "head-hash".to_string(),
            }],
            last_synced_at: 1,
        };
        let mut stage = StageFile {
            branch: "main".to_string(),
            base_changeset_id: Some("cs-head".to_string()),
            assets: vec![AssetDelta {
                path: "Content/A.uasset".to_string(),
                blob_hash: Some("local-hash".to_string()),
                asset_id: None,
            }],
        };

        let update = apply_revert_state(
            &mut workspace,
            &mut stage,
            "Content/A.uasset",
            Some("head-hash"),
            Some("head-hash"),
            None,
        );

        assert_eq!(
            update,
            RevertStateUpdate {
                removed_staged_delta: true,
                staged_delta: false,
            }
        );
        assert_eq!(workspace.checked_out_assets[0].blob_hash, "head-hash");
        assert!(stage.assets.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn revert_execute_e2e_stages_old_snapshot_blob_and_encodes_sync_query() {
        let _guard = cwd_lock().lock().await;
        let original_dir = std::env::current_dir().expect("current dir");
        let root = unique_workspace("stage-old-snapshot");
        std::fs::create_dir_all(&root).expect("workspace dir");
        std::env::set_current_dir(&root).expect("set cwd");

        let repo = "repo";
        let branch = "feature-a";
        let changeset = "cs-old";
        let asset_path = "Content/A.uasset";
        let base_bytes = b"head version";
        let old_bytes = b"old version";
        let base_hash = StorageHash::hash_bytes(base_bytes);
        let old_hash = StorageHash::hash_bytes(old_bytes);
        write_file(&root.join(asset_path), base_bytes);
        let server = FakeServer::start(vec![
            FakeResponse {
                status: "200 OK",
                content_type: "application/json",
                body: sync_response(repo, branch, changeset, asset_path, &old_hash),
            },
            FakeResponse {
                status: "200 OK",
                content_type: "application/octet-stream",
                body: old_bytes.to_vec(),
            },
            FakeResponse {
                status: "200 OK",
                content_type: "application/json",
                body: lock_release_response(asset_path),
            },
        ]);
        setup_revert_workspace(
            &root,
            &server.base_url,
            repo,
            branch,
            asset_path,
            &base_hash,
            vec![],
        );

        let result = execute(RevertArgs {
            asset_path: " Content\\A.uasset ".to_string(),
            repo: Some(repo.to_string()),
            branch: Some(branch.to_string()),
            to_changeset_id: Some(changeset.to_string()),
            yes: true,
            keep_lock: false,
        })
        .await;

        std::env::set_current_dir(&original_dir).expect("restore cwd");
        result.expect("revert executes");
        assert_eq!(
            std::fs::read(root.join(asset_path)).expect("asset"),
            old_bytes
        );
        let workspace: WorkspaceState =
            serde_json::from_slice(&std::fs::read(root.join(".hypertide/workspace.json")).unwrap())
                .unwrap();
        assert_eq!(workspace.checked_out_assets[0].blob_hash, base_hash);
        let stage: StageFile =
            serde_json::from_slice(&std::fs::read(root.join(".hypertide/stage.json")).unwrap())
                .unwrap();
        assert_eq!(stage.assets.len(), 1);
        assert_eq!(stage.assets[0].path, asset_path);
        assert_eq!(
            stage.assets[0].blob_hash.as_deref(),
            Some(old_hash.as_str())
        );

        let requests = server.finish();
        assert!(
            requests[0].starts_with("GET /v2/sync/"),
            "request should target sync endpoint: {}",
            requests[0]
        );
        assert!(
            requests[0].contains("branch="),
            "request should include branch: {}",
            requests[0]
        );
        assert!(
            requests[0].contains("to_changeset_id="),
            "request should include to_changeset_id: {}",
            requests[0]
        );
        assert!(requests[1].starts_with(&format!("GET /v2/storage/download/{old_hash} ")));
        assert!(requests[2].starts_with("POST /v2/locks/release "));
        assert!(requests[2].contains(r#""file_path":"Content/A.uasset""#));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn revert_execute_e2e_clears_stage_when_snapshot_matches_workspace_base() {
        let _guard = cwd_lock().lock().await;
        let original_dir = std::env::current_dir().expect("current dir");
        let root = unique_workspace("clear-stage");
        std::fs::create_dir_all(&root).expect("workspace dir");
        std::env::set_current_dir(&root).expect("set cwd");

        let repo = "repo";
        let branch = "main";
        let asset_path = "Content/A.uasset";
        let base_bytes = b"head version";
        let local_bytes = b"local dirty version";
        let base_hash = StorageHash::hash_bytes(base_bytes);
        write_file(&root.join(asset_path), local_bytes);
        let server = FakeServer::start(vec![
            FakeResponse {
                status: "200 OK",
                content_type: "application/json",
                body: sync_response(repo, branch, "head-cs", asset_path, &base_hash),
            },
            FakeResponse {
                status: "200 OK",
                content_type: "application/octet-stream",
                body: base_bytes.to_vec(),
            },
        ]);
        setup_revert_workspace(
            &root,
            &server.base_url,
            repo,
            branch,
            asset_path,
            &base_hash,
            vec![AssetDelta {
                path: asset_path.to_string(),
                blob_hash: Some(StorageHash::hash_bytes(local_bytes)),
                asset_id: None,
            }],
        );

        let result = execute(RevertArgs {
            asset_path: asset_path.to_string(),
            repo: None,
            branch: None,
            to_changeset_id: None,
            yes: true,
            keep_lock: true,
        })
        .await;

        std::env::set_current_dir(&original_dir).expect("restore cwd");
        result.expect("revert executes");
        assert_eq!(
            std::fs::read(root.join(asset_path)).expect("asset"),
            base_bytes
        );
        let workspace: WorkspaceState =
            serde_json::from_slice(&std::fs::read(root.join(".hypertide/workspace.json")).unwrap())
                .unwrap();
        assert_eq!(workspace.checked_out_assets[0].blob_hash, base_hash);
        let stage: StageFile =
            serde_json::from_slice(&std::fs::read(root.join(".hypertide/stage.json")).unwrap())
                .unwrap();
        assert!(stage.assets.is_empty());

        let requests = server.finish();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].starts_with("GET /v2/sync/repo?branch=main "));
        assert!(requests[1].starts_with(&format!("GET /v2/storage/download/{base_hash} ")));
    }

    #[test]
    fn find_snapshot_asset_returns_none_when_target_missing() {
        let snapshot = SyncResponse {
            repo_id: "repo".to_string(),
            branch: "main".to_string(),
            changeset_id: Some("cs-1".to_string()),
            assets: vec![SyncAsset {
                asset_id: None,
                path: "Content/Other.uasset".to_string(),
                blob_hash: "hash-other".to_string(),
            }],
        };

        let result = find_snapshot_asset(&snapshot, "Content/A.uasset");

        assert!(result.is_none());
    }

    #[test]
    fn deleted_local_file_treated_as_overwrite() {
        // When local file is deleted (local_hash == None) but the base has a hash,
        // overwrites_local_change should be true so the dangerous-operation prompt fires.
        let local_hash: Option<&str> = None;
        let base_hash: Option<&str> = Some("abc123");
        let overwrites_local_change = match (local_hash, base_hash) {
            (Some(local), Some(base)) => local != base,
            (Some(_), None) => true,
            (None, Some(_)) => true,
            (None, None) => false,
        };
        assert!(
            overwrites_local_change,
            "local deletion should count as a local change"
        );
    }

    #[test]
    fn validate_asset_path_rejects_empty_directory_and_wildcards() {
        assert!(normalize_revert_asset_path("").is_err());
        assert!(normalize_revert_asset_path("Content/Foo/").is_err());
        assert!(normalize_revert_asset_path("Content/*.uasset").is_err());
        assert_eq!(
            normalize_revert_asset_path(" Content\\A.uasset ").unwrap(),
            "Content/A.uasset"
        );
    }
}
