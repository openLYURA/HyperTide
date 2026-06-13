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
    // Key: file_path, Value: Lock Info
    // DashMap provides high-concurrency access without heavy Mutex contention
    locks: Arc<DashMap<String, FileLock>>,
    repo: Option<LockRepoPg>,
    lease_seconds: i64,
}

impl LockManager {
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
            tracing::error!("从数据库加载锁信息失败: {e}");
            HyperTideError::Persistence("failed to load locks from db".to_string())
        })?;
        for lock in existing {
            manager.locks.insert(lock.file_path.clone(), lock);
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

        if let Some(repo) = &self.repo {
            let effective_lock = repo
                .acquire_lock_atomic(&requested_lock)
                .await
                .map_err(|e| {
                    tracing::error!("持久化锁信息失败: {e}");
                    HyperTideError::Persistence("failed to persist lock".to_string())
                })?;
            self.locks
                .insert(effective_lock.file_path.clone(), effective_lock.clone());
            if effective_lock.owner_id != owner_id {
                tracing::info!(
                    file_path = %file_path,
                    lock_owner = %effective_lock.owner_id,
                    "文件已被其他用户锁定"
                );
                return Err(HyperTideError::Conflict(
                    "File is already locked".to_string(),
                ));
            }
            return Ok(effective_lock);
        }

        match self.locks.entry(file_path.clone()) {
            Entry::Occupied(mut occupied) => {
                let existing = occupied.get().clone();
                if self.is_expired(&existing) {
                    occupied.insert(requested_lock.clone());
                    Ok(requested_lock)
                } else if existing.owner_id != owner_id {
                    tracing::info!(
                        file_path = %file_path,
                        lock_owner = %existing.owner_id,
                        "文件已被其他用户锁定"
                    );
                    Err(HyperTideError::Conflict(
                        "File is already locked".to_string(),
                    ))
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
        let existing = self
            .locks
            .get(file_path)
            .map(|entry| entry.clone())
            .ok_or_else(|| HyperTideError::NotFound("File is not locked".to_string()))?;

        if existing.owner_id != owner_id {
            tracing::info!(
                file_path = %file_path,
                lock_owner = %existing.owner_id,
                "尝试续期非自己持有的锁"
            );
            return Err(HyperTideError::PermissionDenied(
                "Cannot renew: File is locked by another owner".to_string(),
            ));
        }
        if self.is_expired(&existing) {
            if let Some(repo) = &self.repo {
                repo.delete_lock(file_path).await.map_err(|e| {
                    tracing::error!("清理过期锁失败: {e}");
                    HyperTideError::Persistence("failed to cleanup expired lock".to_string())
                })?;
            }
            self.locks.remove(file_path);
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
                tracing::error!("持久化锁续期失败: {e}");
                HyperTideError::Persistence("failed to persist lock renew".to_string())
            })?;
        }
        self.locks.insert(file_path.to_string(), renewed.clone());
        Ok(renewed)
    }

    /// Unlock a file. Only the owner can unlock.
    pub async fn unlock(&self, file_path: &str, owner_id: &str) -> Result<(), HyperTideError> {
        // We need to check ownership before removing
        if let Some(existing) = self.locks.get(file_path) {
            if existing.owner_id != owner_id {
                tracing::info!(
                    file_path = %file_path,
                    lock_owner = %existing.owner_id,
                    "尝试解锁非自己持有的锁"
                );
                return Err(HyperTideError::PermissionDenied(
                    "Cannot unlock: File is locked by another owner".to_string(),
                ));
            }
        } else {
            return Err(HyperTideError::NotFound("File is not locked".to_string()));
        }

        if let Some(repo) = &self.repo {
            repo.delete_lock(file_path).await.map_err(|e| {
                tracing::error!("删除锁失败: {e}");
                HyperTideError::Persistence("failed to delete lock".to_string())
            })?;
        }

        self.locks.remove(file_path);
        Ok(())
    }

    /// Admin force unlock
    pub async fn force_unlock(&self, file_path: &str) -> Result<bool, HyperTideError> {
        if let Some(repo) = &self.repo {
            repo.delete_lock(file_path).await.map_err(|e| {
                tracing::error!("强制释放锁失败: {e}");
                HyperTideError::Persistence("failed to force release lock".to_string())
            })?;
        }
        Ok(self.locks.remove(file_path).is_some())
    }

    /// List all locks (for administrative view or debugging)
    pub fn list_locks(&self) -> Vec<FileLock> {
        self.locks
            .iter()
            .map(|kv| kv.value().clone())
            .filter(|lock| !self.is_expired(lock))
            .collect()
    }

    /// Query lock by path.
    pub fn get_lock(&self, file_path: &str) -> Option<FileLock> {
        self.locks
            .get(file_path)
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
