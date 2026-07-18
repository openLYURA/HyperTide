//! Storage backend abstraction.
//!
//! Defines the `StorageBackend` trait for content-addressable storage,
//! with a `LocalFsBackend` implementation for local filesystem storage.

use async_trait::async_trait;
use blake3::Hasher;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::AsyncWriteExt;

use crate::core::error::HyperTideError;

/// Error type for storage operations.
#[derive(Debug)]
pub enum StorageError {
    NotFound(String),
    Io(std::io::Error),
    Validation(String),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::NotFound(msg) => write!(f, "not found: {}", msg),
            StorageError::Io(e) => write!(f, "io error: {}", e),
            StorageError::Validation(msg) => write!(f, "validation: {}", msg),
        }
    }
}

impl From<std::io::Error> for StorageError {
    fn from(e: std::io::Error) -> Self {
        StorageError::Io(e)
    }
}

impl From<StorageError> for HyperTideError {
    fn from(e: StorageError) -> Self {
        match e {
            StorageError::NotFound(msg) => HyperTideError::NotFound(msg),
            StorageError::Io(e) => HyperTideError::Persistence(format!("storage io: {}", e)),
            StorageError::Validation(msg) => HyperTideError::Validation(msg),
        }
    }
}

/// Content-addressable storage backend trait.
///
/// All methods take a BLAKE3 hash as the key. Data is stored and retrieved by hash,
/// enabling automatic deduplication.
#[async_trait]
/// Storage backend abstraction for content-addressable storage.
///
/// **Status: Roadmap — not yet integrated into the server.**
/// The server currently uses `StorageManager` directly (local FS CAS).
/// This trait is prepared for future pluggable backends (S3, object storage, etc.)
/// and will be wired in during a follow-up phase.
#[allow(dead_code)]
pub trait StorageBackend: Send + Sync {
    /// Store data and return its hash. If the data already exists, returns the existing hash.
    async fn store(&self, hash: &str, data: &[u8]) -> Result<(), StorageError>;

    /// Retrieve data by hash.
    async fn retrieve(&self, hash: &str) -> Result<Vec<u8>, StorageError>;

    /// Check if data with the given hash exists.
    async fn exists(&self, hash: &str) -> Result<bool, StorageError>;

    /// Delete data by hash. Returns Ok(()) even if the data doesn't exist.
    async fn delete(&self, hash: &str) -> Result<(), StorageError>;

    /// List all stored hashes with an optional prefix filter.
    async fn list(&self, prefix: &str) -> Result<Vec<String>, StorageError>;
}

/// Calculate BLAKE3 hash for content-addressable storage.
#[allow(dead_code)]
pub fn calculate_hash(data: &[u8]) -> String {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize().to_hex().to_string()
}

/// Local filesystem storage backend using content-addressable storage (CAS).
///
/// Files are stored at `objects/{hash[..2]}/{hash[2..]}` for efficient directory distribution.
/// Writes are atomic (temp file + rename).
pub struct LocalFsBackend {
    root: PathBuf,
}

impl LocalFsBackend {
    #[allow(dead_code)]
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    /// Initialize the storage directory.
    #[allow(dead_code)]
    pub async fn init(&self) -> Result<(), StorageError> {
        fs::create_dir_all(self.root.join("objects")).await?;
        fs::create_dir_all(self.root.join("temp")).await?;
        Ok(())
    }

    #[allow(dead_code)]
    fn object_path(&self, hash: &str) -> Option<PathBuf> {
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        let (prefix, rest) = hash.split_at(2);
        Some(self.root.join("objects").join(prefix).join(rest))
    }
}

#[async_trait]
impl StorageBackend for LocalFsBackend {
    async fn store(&self, hash: &str, data: &[u8]) -> Result<(), StorageError> {
        let object_path = self
            .object_path(hash)
            .ok_or_else(|| StorageError::Validation("invalid hash".to_string()))?;
        let actual_hash = calculate_hash(data);
        if actual_hash != hash {
            return Err(StorageError::Validation(format!(
                "content hash mismatch: expected {hash}, got {actual_hash}"
            )));
        }

        // Dedup: skip if already exists
        if object_path.exists() {
            let existing = fs::read(&object_path).await?;
            if calculate_hash(&existing) == hash {
                return Ok(());
            }
            return Err(StorageError::Validation(format!(
                "existing CAS object failed integrity validation: {hash}"
            )));
        }

        // Create subdirectory
        if let Some(parent) = object_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // Atomic write: temp + rename
        let temp_path = self.root.join("temp").join(hash);
        let mut file = fs::File::create(&temp_path).await?;
        file.write_all(data).await?;
        file.sync_all().await?;

        if let Err(rename_err) = fs::rename(&temp_path, &object_path).await {
            // Race: another writer may have won
            if object_path.exists() {
                let _ = fs::remove_file(&temp_path).await;
                return Ok(());
            }
            return Err(StorageError::Io(rename_err));
        }

        Ok(())
    }

    async fn retrieve(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        let object_path = self
            .object_path(hash)
            .ok_or_else(|| StorageError::Validation("invalid hash".to_string()))?;

        if !object_path.exists() {
            return Err(StorageError::NotFound(format!(
                "object not found: {}",
                hash
            )));
        }

        let bytes = fs::read(&object_path).await?;
        let actual_hash = calculate_hash(&bytes);
        if actual_hash != hash {
            return Err(StorageError::Validation(format!(
                "content hash mismatch: expected {hash}, got {actual_hash}"
            )));
        }
        Ok(bytes)
    }

    async fn exists(&self, hash: &str) -> Result<bool, StorageError> {
        let object_path = self
            .object_path(hash)
            .ok_or_else(|| StorageError::Validation("invalid hash".to_string()))?;
        Ok(object_path.exists())
    }

    async fn delete(&self, hash: &str) -> Result<(), StorageError> {
        let object_path = self
            .object_path(hash)
            .ok_or_else(|| StorageError::Validation("invalid hash".to_string()))?;
        if object_path.exists() {
            fs::remove_file(&object_path).await?;
        }
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        let objects_dir = self.root.join("objects");
        let mut hashes = Vec::new();

        let mut entries = fs::read_dir(&objects_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            if !entry.file_type().await?.is_dir() {
                continue;
            }
            let dir_name = entry.file_name();
            let dir_str = dir_name.to_string_lossy();
            // Each subdirectory is a 2-char hash prefix
            if dir_str.len() != 2 {
                continue;
            }

            let mut sub_entries = fs::read_dir(entry.path()).await?;
            while let Some(sub_entry) = sub_entries.next_entry().await? {
                let file_name = sub_entry.file_name();
                let file_str = file_name.to_string_lossy();
                let full_hash = format!("{}{}", dir_str, file_str);
                if full_hash.starts_with(prefix) {
                    hashes.push(full_hash);
                }
            }
        }

        Ok(hashes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_backend(label: &str) -> (std::path::PathBuf, LocalFsBackend) {
        let root = std::env::temp_dir().join(format!(
            "hypertide-storage-backend-{label}-{}",
            uuid::Uuid::new_v4()
        ));
        (root.clone(), LocalFsBackend::new(root))
    }

    #[tokio::test]
    async fn local_backend_rejects_data_that_does_not_match_the_key() {
        let (root, backend) = temp_backend("mismatch");
        backend.init().await.expect("init backend");
        let declared_hash = calculate_hash(b"declared");

        let error = backend
            .store(&declared_hash, b"different")
            .await
            .expect_err("mismatched content must be rejected");
        assert!(error.to_string().contains("content hash mismatch"));

        let _ = std::fs::remove_dir_all(root);
    }

    fn make_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "hypertide-backend-test-{name}-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[tokio::test]
    async fn local_fs_store_retrieve_roundtrip() {
        let root = make_root("roundtrip");
        let backend = LocalFsBackend::new(&root);
        backend.init().await.unwrap();

        let data = b"hello world";
        let hash = calculate_hash(data);

        backend.store(&hash, data).await.unwrap();
        let retrieved = backend.retrieve(&hash).await.unwrap();
        assert_eq!(retrieved, data);

        assert!(backend.exists(&hash).await.unwrap());
        assert!(backend.exists("nonexistent").await.is_err());

        std::fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    async fn local_fs_store_is_idempotent() {
        let root = make_root("idempotent");
        let backend = LocalFsBackend::new(&root);
        backend.init().await.unwrap();

        let data = b"same data";
        let hash = calculate_hash(data);

        backend.store(&hash, data).await.unwrap();
        backend.store(&hash, data).await.unwrap(); // second store should be no-op

        let retrieved = backend.retrieve(&hash).await.unwrap();
        assert_eq!(retrieved, data);

        std::fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    async fn local_fs_delete_removes_object() {
        let root = make_root("delete");
        let backend = LocalFsBackend::new(&root);
        backend.init().await.unwrap();

        let data = b"to be deleted";
        let hash = calculate_hash(data);

        backend.store(&hash, data).await.unwrap();
        assert!(backend.exists(&hash).await.unwrap());

        backend.delete(&hash).await.unwrap();
        assert!(!backend.exists(&hash).await.unwrap());

        // Delete non-existent should be Ok
        backend.delete(&hash).await.unwrap();

        std::fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    async fn local_fs_list_finds_stored_hashes() {
        let root = make_root("list");
        let backend = LocalFsBackend::new(&root);
        backend.init().await.unwrap();

        let data1 = b"data one";
        let data2 = b"data two";
        let hash1 = calculate_hash(data1);
        let hash2 = calculate_hash(data2);

        backend.store(&hash1, data1).await.unwrap();
        backend.store(&hash2, data2).await.unwrap();

        let all = backend.list("").await.unwrap();
        assert!(all.contains(&hash1));
        assert!(all.contains(&hash2));

        // Prefix filter
        let prefix = &hash1[..4];
        let filtered = backend.list(prefix).await.unwrap();
        assert!(filtered.iter().any(|h| h.starts_with(prefix)));

        std::fs::remove_dir_all(root).ok();
    }
}
