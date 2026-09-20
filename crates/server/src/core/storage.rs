//! Storage Manager
//! Handles file upload/download operations with local and S3 backends

mod atomic;

use crate::core::error::HyperTideError;
use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::AsyncWriteExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredFile {
    pub hash: String,
    pub original_path: String,
    pub size_bytes: u64,
    pub stored_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone)]
pub struct StorageManager {
    storage_root: PathBuf,
}

impl StorageManager {
    pub(crate) fn validate_hash(hash: &str) -> Result<(), HyperTideError> {
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(HyperTideError::Validation(
                "Invalid BLAKE3 hash: expected 64 hexadecimal characters".to_string(),
            ));
        }
        Ok(())
    }

    fn object_path(&self, hash: &str) -> Result<PathBuf, HyperTideError> {
        Self::validate_hash(hash)?;
        let (prefix, rest) = hash.split_at(2);
        Ok(self.storage_root.join("objects").join(prefix).join(rest))
    }

    async fn check_regular_object(path: &Path, context: &str) -> Result<bool, String> {
        let metadata = match fs::symlink_metadata(path).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(format!("Failed to check {context}: {error}")),
        };
        if !metadata.file_type().is_file() {
            return Err(format!(
                "CAS object path is not a regular file: {}",
                path.display()
            ));
        }
        Ok(true)
    }

    /// Create a new storage manager with the given root directory
    pub fn new(storage_root: impl AsRef<Path>) -> Self {
        Self {
            storage_root: storage_root.as_ref().to_path_buf(),
        }
    }

    /// Initialize storage directory structure
    pub async fn init(&self) -> Result<(), HyperTideError> {
        // Create storage directories: objects/, temp/
        let objects_dir = self.storage_root.join("objects");
        let temp_dir = self.storage_root.join("temp");

        fs::create_dir_all(&objects_dir).await.map_err(|e| {
            HyperTideError::Persistence(format!("Failed to create objects dir: {}", e))
        })?;
        fs::create_dir_all(&temp_dir).await.map_err(|e| {
            HyperTideError::Persistence(format!("Failed to create temp dir: {}", e))
        })?;

        Ok(())
    }

    /// Verify that required storage directories exist and accept writes.
    pub async fn health_check(&self) -> Result<(), HyperTideError> {
        let objects_dir = self.storage_root.join("objects");
        let temp_dir = self.storage_root.join("temp");

        for (path, label) in [(&objects_dir, "objects"), (&temp_dir, "temp")] {
            let metadata = fs::metadata(path).await.map_err(|e| {
                HyperTideError::Persistence(format!("Storage {label} dir is unavailable: {e}"))
            })?;
            if !metadata.is_dir() {
                return Err(HyperTideError::Persistence(format!(
                    "Storage {label} path is not a directory"
                )));
            }
        }

        let probe_path = temp_dir.join(".hypertide-healthcheck");
        let mut file = fs::File::create(&probe_path).await.map_err(|e| {
            HyperTideError::Persistence(format!("Storage temp dir is not writable: {e}"))
        })?;
        file.write_all(chrono::Utc::now().to_rfc3339().as_bytes())
            .await
            .map_err(|e| HyperTideError::Persistence(format!("Storage probe write failed: {e}")))?;
        file.sync_all()
            .await
            .map_err(|e| HyperTideError::Persistence(format!("Storage probe sync failed: {e}")))?;
        Ok(())
    }

    /// Calculate BLAKE3 hash of file content
    pub fn calculate_hash(data: &[u8]) -> String {
        let mut hasher = Hasher::new();
        hasher.update(data);
        hasher.finalize().to_hex().to_string()
    }

    /// Store file content, returning its content-addressed identity.
    /// Existing objects are verified with bounded memory before deduplication.
    pub async fn store(
        &self,
        data: &[u8],
        original_path: &str,
    ) -> Result<StoredFile, HyperTideError> {
        let hash = Self::calculate_hash(data);
        atomic::store(&self.storage_root, &hash, data).await?;

        Ok(StoredFile {
            hash,
            original_path: original_path.to_string(),
            size_bytes: data.len() as u64,
            stored_at: chrono::Utc::now(),
        })
    }

    /// Retrieve file content by hash
    pub async fn retrieve(&self, hash: &str) -> Result<Vec<u8>, HyperTideError> {
        let object_path = self.object_path(hash)?;

        if !Self::check_regular_object(&object_path, "object existence before retrieve")
            .await
            .map_err(HyperTideError::Persistence)?
        {
            return Err(HyperTideError::NotFound(format!(
                "Object not found: {}",
                hash
            )));
        }

        let bytes = fs::read(&object_path)
            .await
            .map_err(|e| HyperTideError::Persistence(format!("Failed to read object: {}", e)))?;
        let actual_hash = Self::calculate_hash(&bytes);
        if actual_hash != hash {
            return Err(HyperTideError::Persistence(format!(
                "CAS object integrity mismatch: expected {hash}, got {actual_hash}"
            )));
        }
        Ok(bytes)
    }

    /// Check if a file with given hash exists
    pub async fn exists(&self, hash: &str) -> Result<bool, String> {
        let object_path = self.object_path(hash).map_err(|error| error.to_string())?;
        Self::check_regular_object(&object_path, "object existence").await
    }

    /// Get the local file path for a hash (for direct access)
    pub fn get_path(&self, hash: &str) -> Option<PathBuf> {
        self.object_path(hash).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::StorageManager;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn make_storage_root(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "hypertide-storage-tests-{name}-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).expect("create temp storage root");
        root
    }

    #[tokio::test]
    async fn concurrent_same_hash_store_is_idempotent() {
        let root = make_storage_root("concurrent");
        let manager = StorageManager::new(&root);
        manager.init().await.expect("init storage");

        let payload = b"same-bytes-for-all-writers".to_vec();
        let mut tasks = Vec::new();

        for _ in 0..16 {
            let mgr = manager.clone();
            let data = payload.clone();
            tasks.push(tokio::spawn(
                async move { mgr.store(&data, "foo.bin").await },
            ));
        }

        let mut results = Vec::new();
        for task in tasks {
            results.push(task.await.expect("join task").expect("store success"));
        }
        let first_hash = results[0].hash.clone();

        for stored in results {
            assert_eq!(stored.hash, first_hash);
        }

        let object = manager
            .retrieve(&first_hash)
            .await
            .expect("retrieve object");
        assert_eq!(object, payload);
        std::fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    async fn health_check_requires_initialized_storage_dirs() {
        let root = make_storage_root("health-uninitialized");
        let manager = StorageManager::new(&root);

        let error = manager
            .health_check()
            .await
            .expect_err("uninitialized storage should not be ready");
        assert!(error
            .to_string()
            .contains("Storage objects dir is unavailable"));

        manager.init().await.expect("init storage");
        manager
            .health_check()
            .await
            .expect("initialized storage is ready");

        std::fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn store_reports_permission_error_on_objects_dir() {
        let root = make_storage_root("permission-store");
        let manager = StorageManager::new(&root);
        manager.init().await.expect("init storage");

        let objects = root.join("objects");
        let mut perms = std::fs::metadata(&objects).expect("metadata").permissions();
        perms.set_mode(0o000);
        std::fs::set_permissions(&objects, perms).expect("chmod objects");

        let permission_attempt = manager.store(b"blocked", "blocked.bin").await;

        let mut restore = std::fs::metadata(&objects).expect("metadata").permissions();
        restore.set_mode(0o755);
        std::fs::set_permissions(&objects, restore).expect("restore chmod");

        if let Err(error) = permission_attempt {
            assert!(
                error.to_string().contains("Failed to create object subdir")
                    || error
                        .to_string()
                        .contains("Failed to check object existence before store")
            );
        } else {
            // In privileged environments permission bits may not block access;
            // fall back to a deterministic filesystem failure.
            let fallback_hash = StorageManager::calculate_hash(b"blocked-fallback");
            let blocked_prefix = root.join("objects").join(&fallback_hash[..2]);
            std::fs::write(&blocked_prefix, b"not-a-directory").expect("poison prefix dir");
            let fallback = manager.store(b"blocked-fallback", "blocked.bin").await;
            let fallback_error = fallback.expect_err("store should fail on poisoned prefix dir");
            assert!(
                fallback_error
                    .to_string()
                    .contains("Failed to create object subdir")
                    || fallback_error
                        .to_string()
                        .contains("Failed to check object existence before store")
            );
            std::fs::remove_file(blocked_prefix).ok();
        }

        std::fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    async fn retrieve_and_exists_report_errors_when_target_dir_is_broken() {
        let root = make_storage_root("broken-target");
        let manager = StorageManager::new(&root);
        manager.init().await.expect("init storage");

        let stored = manager
            .store(b"hello", "hello.bin")
            .await
            .expect("store initial object");

        let (prefix, rest) = stored.hash.split_at(2);
        let object_dir = root.join("objects").join(prefix);
        let object_path = object_dir.join(rest);

        std::fs::remove_file(&object_path).expect("remove object file");
        std::fs::remove_dir_all(&object_dir).expect("remove hash directory");
        std::fs::write(&object_dir, b"not-a-directory").expect("replace directory with file");

        let retrieve_err = manager
            .retrieve(&stored.hash)
            .await
            .expect_err("retrieve should fail");
        let retrieve_msg = retrieve_err.to_string();
        assert!(
            retrieve_msg.contains("Failed to check object existence before retrieve")
                || retrieve_msg.contains("Object not found")
        );
        let exists_result = manager.exists(&stored.hash).await;
        match exists_result {
            Ok(false) => {}
            Ok(true) => panic!("exists should not return true for broken target"),
            Err(error) => {
                assert!(error.contains("Failed to check object existence"));
            }
        }

        std::fs::remove_file(object_dir).ok();
        std::fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    async fn rejects_non_blake3_hashes_before_resolving_storage_paths() {
        let root = make_storage_root("invalid-hash");
        let manager = StorageManager::new(&root);
        manager.init().await.expect("init storage");

        let traversal = manager
            .retrieve("../outside-file")
            .await
            .expect_err("path traversal must be rejected");
        assert!(traversal.to_string().contains("Invalid BLAKE3 hash"));
        assert!(manager.exists("../outside-file").await.is_err());
        assert!(manager.get_path("../outside-file").is_none());

        std::fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn exists_and_retrieve_reject_fifo_object_entries() {
        let root = make_storage_root("fifo-object");
        let manager = StorageManager::new(&root);
        manager.init().await.expect("init storage");
        let hash = StorageManager::calculate_hash(b"expected");
        let object_path = manager.get_path(&hash).expect("valid object path");
        std::fs::create_dir_all(object_path.parent().expect("object parent"))
            .expect("create object parent");
        let status = std::process::Command::new("mkfifo")
            .arg(&object_path)
            .status()
            .expect("run mkfifo");
        assert!(status.success(), "mkfifo should succeed");

        let exists_error = manager
            .exists(&hash)
            .await
            .expect_err("FIFO must be a storage inconsistency");
        assert!(exists_error.contains("not a regular file"));

        let retrieve_error = manager
            .retrieve(&hash)
            .await
            .expect_err("FIFO must be rejected before reading");
        assert!(retrieve_error.to_string().contains("not a regular file"));

        std::fs::remove_file(object_path).ok();
        std::fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    async fn retrieve_rejects_corrupt_content_under_a_valid_hash() {
        let root = make_storage_root("corrupt-object");
        let manager = StorageManager::new(&root);
        manager.init().await.expect("init storage");
        let expected_hash = StorageManager::calculate_hash(b"expected");
        let object_path = manager.get_path(&expected_hash).expect("valid object path");
        std::fs::create_dir_all(object_path.parent().expect("object parent"))
            .expect("create object parent");
        std::fs::write(&object_path, b"corrupt").expect("write corrupt object");

        let error = manager
            .retrieve(&expected_hash)
            .await
            .expect_err("corrupt object must be rejected");
        assert!(error.to_string().contains("integrity mismatch"));

        std::fs::remove_dir_all(root).ok();
    }
}
