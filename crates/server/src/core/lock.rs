use chrono::{DateTime, Utc};

use crate::core::error::HyperTideError;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;

pub mod repo_pg;
use self::repo_pg::LockRepoPg;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileLock {
    pub file_path: String,
    pub owner_id: String,
    pub locked_at: DateTime<Utc>,
    pub lease_expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub repo_id: String,
    #[serde(default = "default_scope")]
    pub scope: String,
}

fn default_scope() -> String {
    "asset".to_string()
}

#[derive(Clone)]
pub struct LockManager {
    // Key: repo_id + scope + file_path, Value: Lock Info
    // DashMap provides high-concurrency access without heavy Mutex contention
    locks: Arc<DashMap<(String, String, String), FileLock>>,
    repo: Option<LockRepoPg>,
    lease_seconds: i64,
}

impl LockManager {
    fn lock_key(repo_id: &str, scope: &str, file_path: &str) -> (String, String, String) {
        (
            repo_id.to_string(),
            scope.to_string(),
            file_path.to_string(),
        )
    }

    pub fn new() -> Self {
        Self {
            locks: Arc::new(DashMap::new()),
            repo: None,
            lease_seconds: default_lease_seconds(),
        }
    }

    pub async fn with_pg(pool: PgPool) -> Result<Self, HyperTideError> {
        let repo = LockRepoPg::new(pool);
        let manager = Self {
            locks: Arc::new(DashMap::new()),
            repo: Some(repo.clone()),
            lease_seconds: default_lease_seconds(),
        };

        let existing = repo.load_locks().await.map_err(|e| {
            HyperTideError::Persistence(format!("failed to load locks from db: {e}"))
        })?;
        for lock in existing {
            let key = Self::lock_key(&lock.repo_id, &lock.scope, &lock.file_path);
            manager.locks.insert(key, lock);
        }

        Ok(manager)
    }

    /// Attempt to lock a file. Returns true if successful, false if already locked by someone else.
    pub async fn try_lock(
        &self,
        file_path: String,
        owner_id: String,
    ) -> Result<FileLock, HyperTideError> {
        self.try_lock_with_repo(file_path, owner_id, "", "asset")
            .await
    }

    /// Attempt to lock a file with repo_id and scope context.
    pub async fn try_lock_with_repo(
        &self,
        file_path: String,
        owner_id: String,
        repo_id: &str,
        scope: &str,
    ) -> Result<FileLock, HyperTideError> {
        let requested_lock = FileLock {
            file_path: file_path.clone(),
            owner_id: owner_id.clone(),
            locked_at: Utc::now(),
            lease_expires_at: Some(self.next_lease_expiry()),
            repo_id: repo_id.to_string(),
            scope: scope.to_string(),
        };
        let lock_key = Self::lock_key(repo_id, scope, &file_path);

        if let Some(repo) = &self.repo {
            let effective_lock = repo
                .acquire_lock_atomic(&requested_lock)
                .await
                .map_err(|e| HyperTideError::Persistence(format!("failed to persist lock: {e}")))?;
            let effective_key = Self::lock_key(
                &effective_lock.repo_id,
                &effective_lock.scope,
                &effective_lock.file_path,
            );
            self.locks.insert(effective_key, effective_lock.clone());
            if effective_lock.owner_id != owner_id {
                return Err(HyperTideError::Conflict(format!(
                    "File is already locked by {}",
                    effective_lock.owner_id
                )));
            }
            return Ok(effective_lock);
        }

        match self.locks.entry(lock_key) {
            Entry::Occupied(mut occupied) => {
                let existing = occupied.get().clone();
                if self.is_expired(&existing) {
                    occupied.insert(requested_lock.clone());
                    Ok(requested_lock)
                } else if existing.owner_id != owner_id {
                    Err(HyperTideError::Conflict(format!(
                        "File is already locked by {}",
                        existing.owner_id
                    )))
                } else {
                    Ok(existing)
                }
            }
            Entry::Vacant(vacant) => {
                vacant.insert(requested_lock.clone());
                Ok(requested_lock)
            }
        }
    }

    pub async fn renew_lock(
        &self,
        file_path: &str,
        owner_id: &str,
    ) -> Result<FileLock, HyperTideError> {
        self.renew_lock_with_repo(file_path, owner_id, "", "asset")
            .await
    }

    pub async fn renew_lock_with_repo(
        &self,
        file_path: &str,
        owner_id: &str,
        repo_id: &str,
        scope: &str,
    ) -> Result<FileLock, HyperTideError> {
        let lock_key = Self::lock_key(repo_id, scope, file_path);
        let existing = self
            .locks
            .get(&lock_key)
            .map(|entry| entry.clone())
            .ok_or_else(|| HyperTideError::NotFound("File is not locked".to_string()))?;

        if existing.owner_id != owner_id {
            return Err(HyperTideError::PermissionDenied(format!(
                "Cannot renew: File is locked by {}",
                existing.owner_id
            )));
        }
        if self.is_expired(&existing) {
            if let Some(repo) = &self.repo {
                repo.delete_lock(repo_id, scope, file_path)
                    .await
                    .map_err(|e| {
                        HyperTideError::Persistence(format!("failed to cleanup expired lock: {e}"))
                    })?;
            }
            self.locks.remove(&lock_key);
            return Err(HyperTideError::Conflict(
                "Cannot renew: lock lease expired".to_string(),
            ));
        }

        let renewed = FileLock {
            lease_expires_at: Some(self.next_lease_expiry()),
            ..existing
        };

        if let Some(repo) = &self.repo {
            repo.upsert_lock(&renewed).await.map_err(|e| {
                HyperTideError::Persistence(format!("failed to persist lock renew: {e}"))
            })?;
        }
        self.locks.insert(lock_key, renewed.clone());
        Ok(renewed)
    }

    /// Unlock a file. Only the owner can unlock.
    pub async fn unlock(&self, file_path: &str, owner_id: &str) -> Result<(), HyperTideError> {
        self.unlock_with_repo(file_path, owner_id, "", "asset")
            .await
            .map(|_| ())
    }

    pub async fn unlock_with_repo(
        &self,
        file_path: &str,
        owner_id: &str,
        repo_id: &str,
        scope: &str,
    ) -> Result<FileLock, HyperTideError> {
        let lock_key = Self::lock_key(repo_id, scope, file_path);
        // We need to check ownership before removing
        let existing = if let Some(existing) = self.locks.get(&lock_key) {
            if existing.owner_id != owner_id {
                return Err(HyperTideError::PermissionDenied(format!(
                    "Cannot unlock: File is locked by {}",
                    existing.owner_id
                )));
            }
            existing.clone()
        } else {
            return Err(HyperTideError::NotFound("File is not locked".to_string()));
        };

        if let Some(repo) = &self.repo {
            repo.delete_lock(repo_id, scope, file_path)
                .await
                .map_err(|e| HyperTideError::Persistence(format!("failed to delete lock: {e}")))?;
        }

        self.locks.remove(&lock_key);
        Ok(existing)
    }

    /// Admin force unlock
    pub async fn force_unlock(&self, file_path: &str) -> Result<bool, HyperTideError> {
        self.force_unlock_with_repo(file_path, "", "asset").await
    }

    pub async fn force_unlock_with_repo(
        &self,
        file_path: &str,
        repo_id: &str,
        scope: &str,
    ) -> Result<bool, HyperTideError> {
        let lock_key = Self::lock_key(repo_id, scope, file_path);
        if let Some(repo) = &self.repo {
            repo.delete_lock(repo_id, scope, file_path)
                .await
                .map_err(|e| {
                    HyperTideError::Persistence(format!("failed to force release lock: {e}"))
                })?;
        }
        Ok(self.locks.remove(&lock_key).is_some())
    }

    /// List all locks (for administrative view or debugging)
    pub fn list_locks(&self) -> Vec<FileLock> {
        self.locks
            .iter()
            .map(|kv| kv.value().clone())
            .filter(|lock| !self.is_expired(lock))
            .collect()
    }

    pub fn list_locks_with_repo(&self, repo_id: &str, scope: &str) -> Vec<FileLock> {
        self.locks
            .iter()
            .map(|entry| entry.value().clone())
            .filter(|lock| lock.repo_id == repo_id && lock.scope == scope && !self.is_expired(lock))
            .collect()
    }

    /// Query lock by path.
    pub fn get_lock(&self, file_path: &str) -> Option<FileLock> {
        self.get_lock_with_repo("", "asset", file_path)
    }

    pub fn get_lock_with_repo(
        &self,
        repo_id: &str,
        scope: &str,
        file_path: &str,
    ) -> Option<FileLock> {
        let lock_key = Self::lock_key(repo_id, scope, file_path);
        self.locks
            .get(&lock_key)
            .map(|entry| entry.clone())
            .filter(|lock| !self.is_expired(lock))
    }

    fn next_lease_expiry(&self) -> DateTime<Utc> {
        Utc::now() + chrono::Duration::seconds(self.lease_seconds.max(30))
    }

    fn is_expired(&self, lock: &FileLock) -> bool {
        lock.lease_expires_at
            .map(|expiry| expiry <= Utc::now())
            .unwrap_or(false)
    }
}

fn default_lease_seconds() -> i64 {
    std::env::var("LOCK_LEASE_SECS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(300)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn identical_paths_are_isolated_by_repo() {
        let manager = LockManager::new();
        let first = manager
            .try_lock_with_repo(
                "Content/A.uasset".to_string(),
                "alice".to_string(),
                "repo-a",
                "asset",
            )
            .await
            .expect("repo-a lock");
        let second = manager
            .try_lock_with_repo(
                "Content/A.uasset".to_string(),
                "bob".to_string(),
                "repo-b",
                "asset",
            )
            .await
            .expect("repo-b lock");

        assert_eq!(first.owner_id, "alice");
        assert_eq!(second.owner_id, "bob");
        manager
            .unlock_with_repo("Content/A.uasset", "alice", "repo-a", "asset")
            .await
            .expect("release repo-a");
        assert!(manager
            .get_lock_with_repo("repo-a", "asset", "Content/A.uasset")
            .is_none());
        assert_eq!(
            manager
                .get_lock_with_repo("repo-b", "asset", "Content/A.uasset")
                .expect("repo-b remains")
                .owner_id,
            "bob"
        );
    }
}
