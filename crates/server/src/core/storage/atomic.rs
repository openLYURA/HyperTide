//! Private staging and verified publication for local CAS objects.

use std::path::Path;

use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::core::error::HyperTideError;

/// Verify an existing object without allocating another object-sized buffer.
async fn matches_existing(
    object_path: &Path,
    hash: &str,
    size_bytes: u64,
) -> Result<bool, HyperTideError> {
    let mut file = match fs::File::open(object_path).await {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(HyperTideError::Persistence(format!(
                "Failed to check object existence before store: {error}"
            )));
        }
    };
    let metadata = file.metadata().await.map_err(|error| {
        HyperTideError::Persistence(format!("Failed to inspect existing CAS object: {error}"))
    })?;
    if !metadata.is_file() {
        return Err(HyperTideError::Persistence(
            "CAS object path is not a regular file".to_string(),
        ));
    }
    if metadata.len() != size_bytes {
        return Ok(false);
    }

    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).await.map_err(|error| {
            HyperTideError::Persistence(format!("Failed to verify existing CAS object: {error}"))
        })?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize().to_hex().as_str() == hash)
}

pub(super) async fn store(root: &Path, hash: &str, data: &[u8]) -> Result<(), HyperTideError> {
    // The caller supplies the BLAKE3 digest calculated from data.
    let (prefix, rest) = hash.split_at(2);
    let object_dir = root.join("objects").join(prefix);
    let object_path = object_dir.join(rest);
    let size_bytes = data.len() as u64;
    if matches_existing(&object_path, hash, size_bytes).await? {
        return Ok(());
    }

    fs::create_dir_all(&object_dir).await.map_err(|error| {
        HyperTideError::Persistence(format!("Failed to create object subdir: {error}"))
    })?;

    // A shared temp/<hash> inode lets a competing writer truncate or mutate an
    // object after another writer has published it. Every operation owns its
    // own staging file, including operations from independent server instances.
    let temp_path = root
        .join("temp")
        .join(format!("{hash}-{}.tmp", uuid::Uuid::new_v4()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .await
        .map_err(|error| {
            HyperTideError::Persistence(format!("Failed to create temp file: {error}"))
        })?;

    let write_result = async {
        file.write_all(data).await.map_err(|error| {
            HyperTideError::Persistence(format!("Failed to write data: {error}"))
        })?;
        file.sync_all().await.map_err(|error| {
            HyperTideError::Persistence(format!("Failed to sync file: {error}"))
        })?;
        Ok::<(), HyperTideError>(())
    }
    .await;
    // Release our handle before rename and cleanup, including on Windows.
    drop(file);

    let result = match write_result {
        Err(error) => Err(error),
        Ok(()) => match fs::rename(&temp_path, &object_path).await {
            Ok(()) => Ok(()),
            Err(rename_error) => {
                // A destination's mere existence does not prove a racing writer
                // published valid content. Verify it before reporting success.
                match matches_existing(&object_path, hash, size_bytes).await {
                    Ok(true) => Ok(()),
                    Ok(false) => Err(HyperTideError::Persistence(format!(
                        "Failed to move file to storage: {rename_error}"
                    ))),
                    Err(verify_error) => Err(HyperTideError::Persistence(format!(
                        "Failed to move file to storage: {rename_error}; \
                         additionally failed to verify destination: {verify_error}"
                    ))),
                }
            }
        },
    };

    // Never unlink the old CAS object before the replacement is complete. Only
    // our private staging file is eligible for cleanup after a normal return.
    if let Err(error) = fs::remove_file(&temp_path).await {
        if error.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(path = %temp_path.display(), %error, "Failed to clean CAS staging file");
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use super::*;
    use crate::core::storage::StorageManager;

    struct TestStorage {
        root: PathBuf,
        manager: StorageManager,
    }

    impl TestStorage {
        async fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("hypertide-atomic-cas-{}", uuid::Uuid::new_v4()));
            let manager = StorageManager::new(&root);
            manager.init().await.expect("init storage");
            Self { root, manager }
        }

        async fn seed_object(&self, hash: &str, bytes: &[u8]) -> PathBuf {
            let path = self.manager.get_path(hash).expect("valid hash");
            fs::create_dir_all(path.parent().expect("parent"))
                .await
                .expect("create object directory");
            fs::write(&path, bytes).await.expect("seed object");
            path
        }
    }

    impl Drop for TestStorage {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[tokio::test]
    async fn store_does_not_reuse_another_writers_staging_file() {
        let storage = TestStorage::new().await;
        let data = b"complete object";
        let hash = StorageManager::calculate_hash(data);
        let legacy_temp = storage.root.join("temp").join(&hash);
        fs::write(&legacy_temp, b"another writer is still using this file")
            .await
            .expect("create existing staging file");

        storage
            .manager
            .store(data, "asset.bin")
            .await
            .expect("store");

        assert_eq!(
            fs::read(&legacy_temp)
                .await
                .expect("other staging file remains"),
            b"another writer is still using this file"
        );
        assert_eq!(
            storage.manager.retrieve(&hash).await.expect("retrieve"),
            data
        );
    }

    #[tokio::test]
    async fn store_repairs_same_size_corruption() {
        let storage = TestStorage::new().await;
        let data = b"expected";
        let hash = StorageManager::calculate_hash(data);
        storage.seed_object(&hash, b"corrupt!").await;

        storage
            .manager
            .store(data, "asset.bin")
            .await
            .expect("repair");

        assert_eq!(
            storage.manager.retrieve(&hash).await.expect("retrieve"),
            data
        );
    }

    #[tokio::test]
    async fn staging_failure_preserves_the_existing_object() {
        let storage = TestStorage::new().await;
        let data = b"expected replacement";
        let hash = StorageManager::calculate_hash(data);
        let object = storage.seed_object(&hash, b"old").await;
        let temp = storage.root.join("temp");
        fs::remove_dir(&temp)
            .await
            .expect("remove staging directory");
        fs::write(&temp, b"not a directory")
            .await
            .expect("block staging");

        assert!(storage.manager.store(data, "asset.bin").await.is_err());
        assert_eq!(fs::read(object).await.expect("old object remains"), b"old");
    }

    #[tokio::test]
    async fn a_directory_at_the_object_path_is_not_a_dedup_hit() {
        let storage = TestStorage::new().await;
        let data = b"expected";
        let hash = StorageManager::calculate_hash(data);
        let object = storage.manager.get_path(&hash).expect("valid hash");
        fs::create_dir_all(&object)
            .await
            .expect("create invalid target");

        assert!(storage.manager.store(data, "asset.bin").await.is_err());
        assert!(object.is_dir());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn independent_concurrent_writers_publish_complete_content_and_clean_staging() {
        let storage = TestStorage::new().await;
        let data = Arc::new(vec![0x5a_u8; 256 * 1024]);
        let hash = StorageManager::calculate_hash(&data);
        let barrier = Arc::new(tokio::sync::Barrier::new(16));
        let mut writers = Vec::new();
        for _ in 0..16 {
            let manager = StorageManager::new(&storage.root);
            let data = Arc::clone(&data);
            let barrier = Arc::clone(&barrier);
            writers.push(tokio::spawn(async move {
                barrier.wait().await;
                manager.store(&data, "asset.bin").await
            }));
        }
        for writer in writers {
            assert_eq!(writer.await.expect("join").expect("store").hash, hash);
        }

        assert_eq!(
            storage.manager.retrieve(&hash).await.expect("retrieve"),
            *data
        );
        assert!(fs::read_dir(storage.root.join("temp"))
            .await
            .expect("read staging directory")
            .next_entry()
            .await
            .expect("read staging entry")
            .is_none());
    }
}
