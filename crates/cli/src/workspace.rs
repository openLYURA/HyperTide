use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Serialize};

#[derive(Debug, Clone)]
pub struct StatePaths {
    pub state_dir: PathBuf,
    pub profile_path: PathBuf,
    pub stage_path: PathBuf,
    pub workspace_path: PathBuf,
    pub cache_dir: PathBuf,
}

pub fn state_paths_from(base_dir: &Path) -> StatePaths {
    let state_dir = base_dir.join(".hypertide");
    StatePaths {
        profile_path: state_dir.join("profile.json"),
        stage_path: state_dir.join("stage.json"),
        workspace_path: state_dir.join("workspace.json"),
        cache_dir: state_dir.join("cache").join("objects"),
        state_dir,
    }
}

pub fn ensure_state_dirs(paths: &StatePaths) -> Result<()> {
    if !paths.state_dir.exists() {
        fs::create_dir_all(&paths.state_dir)?;
    }
    // Restrict the state directory to the owner: it holds credentials.
    harden_dir_permissions(&paths.state_dir);
    // Never let the local state (including plaintext credentials) be committed.
    ensure_state_gitignore(&paths.state_dir);
    if !paths.cache_dir.exists() {
        fs::create_dir_all(&paths.cache_dir)?;
    }
    Ok(())
}

fn ensure_state_gitignore(state_dir: &Path) {
    let gitignore = state_dir.join(".gitignore");
    if !gitignore.exists() {
        // Ignore everything under .hypertide/, including this file itself.
        let _ = fs::write(&gitignore, "*\n");
    }
}

#[cfg(unix)]
fn harden_dir_permissions(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn harden_dir_permissions(_dir: &Path) {}

#[cfg(unix)]
fn harden_file_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn harden_file_permissions(_path: &Path) {}

pub fn load_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(serde_json::from_str(&content)?)
}

pub fn save_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(value)?;
    // Atomic write: serialize to a sibling temp file, tighten permissions before
    // it holds any data, then rename over the target so a crash/IO error mid-write
    // can never truncate or corrupt existing state (e.g. profile.json credentials).
    let temp_path = temp_sibling(path);
    fs::write(&temp_path, &bytes)
        .with_context(|| format!("failed to write {}", temp_path.display()))?;
    harden_file_permissions(&temp_path);
    if let Err(err) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(err).with_context(|| format!("failed to replace {}", path.display()));
    }
    Ok(())
}

fn temp_sibling(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "state".to_string());
    let temp_name = format!(".{}.tmp.{}", file_name, std::process::id());
    match path.parent() {
        Some(parent) => parent.join(temp_name),
        None => PathBuf::from(temp_name),
    }
}

pub fn cache_object_path(paths: &StatePaths, hash: &str) -> PathBuf {
    paths.cache_dir.join(hash)
}
