use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::{FromRow, PgPool};

use crate::core::lock::FileLock;

#[derive(Clone)]
pub struct LockRepoPg {
    pool: PgPool,
}

#[derive(Debug, Deserialize, FromRow)]
struct LockRow {
    file_path: String,
    owner_id: String,
    locked_at: DateTime<Utc>,
    lease_expires_at: Option<DateTime<Utc>>,
    repo_id: String,
    scope: String,
}

impl LockRepoPg {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn load_locks(&self) -> Result<Vec<FileLock>, sqlx::Error> {
        let rows = sqlx::query_as::<_, LockRow>(
            r#"
            SELECT file_path, owner_id, locked_at, lease_expires_at, repo_id, scope
            FROM locks
            WHERE force_released = FALSE
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| FileLock {
                file_path: row.file_path,
                owner_id: row.owner_id,
                locked_at: row.locked_at,
                lease_expires_at: row.lease_expires_at,
                repo_id: row.repo_id,
                scope: row.scope,
            })
            .collect())
    }

    /// Renew/insert a lock, but never steal one: on conflict the lease is only
    /// extended when the existing row is still owned by the same principal.
    /// Returns `false` (0 rows) when a different owner holds the DB lock, so a
    /// stale in-memory view cannot overwrite the authoritative owner.
    pub async fn upsert_lock(&self, lock: &FileLock) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            INSERT INTO locks (file_path, owner_id, locked_at, lease_expires_at, force_released, repo_id, scope)
            VALUES ($1, $2, $3, $4, FALSE, $5, $6)
            ON CONFLICT (repo_id, scope, file_path)
            DO UPDATE SET
                owner_id = EXCLUDED.owner_id,
                locked_at = EXCLUDED.locked_at,
                lease_expires_at = EXCLUDED.lease_expires_at,
                force_released = FALSE
            WHERE locks.owner_id = EXCLUDED.owner_id
            "#,
        )
        .bind(&lock.file_path)
        .bind(&lock.owner_id)
        .bind(lock.locked_at)
        .bind(lock.lease_expires_at)
        .bind(&lock.repo_id)
        .bind(&lock.scope)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn acquire_lock_atomic(&self, lock: &FileLock) -> Result<FileLock, sqlx::Error> {
        let row = sqlx::query_as::<_, LockRow>(
            r#"
            WITH legacy_lock AS (
                SELECT file_path, owner_id, locked_at, lease_expires_at, repo_id, scope
                FROM locks
                WHERE $5 <> ''
                    AND repo_id = ''
                    AND scope = $6
                    AND file_path = $1
                    AND force_released = FALSE
                    AND (lease_expires_at IS NULL OR lease_expires_at > NOW())
            ),
            attempted AS (
                INSERT INTO locks (file_path, owner_id, locked_at, lease_expires_at, force_released, repo_id, scope)
                SELECT $1, $2, $3, $4, FALSE, $5, $6
                WHERE NOT EXISTS (SELECT 1 FROM legacy_lock)
                ON CONFLICT (repo_id, scope, file_path)
                DO UPDATE SET
                    owner_id = EXCLUDED.owner_id,
                    locked_at = EXCLUDED.locked_at,
                    lease_expires_at = EXCLUDED.lease_expires_at,
                    force_released = FALSE
                WHERE locks.owner_id = EXCLUDED.owner_id
                    OR locks.lease_expires_at IS NULL
                    OR locks.lease_expires_at <= NOW()
                RETURNING file_path, owner_id, locked_at, lease_expires_at, repo_id, scope
            ),
            current_lock AS (
                SELECT file_path, owner_id, locked_at, lease_expires_at, repo_id, scope
                FROM locks
                WHERE repo_id = $5 AND scope = $6 AND file_path = $1 AND force_released = FALSE
            )
            SELECT file_path, owner_id, locked_at, lease_expires_at, repo_id, scope
            FROM (
                SELECT file_path, owner_id, locked_at, lease_expires_at, repo_id, scope, 0 AS priority
                FROM legacy_lock
                UNION ALL
                SELECT file_path, owner_id, locked_at, lease_expires_at, repo_id, scope, 1 AS priority
                FROM attempted
                UNION ALL
                SELECT file_path, owner_id, locked_at, lease_expires_at, repo_id, scope, 2 AS priority
                FROM current_lock
            ) candidates
            ORDER BY priority
            LIMIT 1
            "#,
        )
        .bind(&lock.file_path)
        .bind(&lock.owner_id)
        .bind(lock.locked_at)
        .bind(lock.lease_expires_at)
        .bind(&lock.repo_id)
        .bind(&lock.scope)
        .fetch_one(&self.pool)
        .await?;

        Ok(FileLock {
            file_path: row.file_path,
            owner_id: row.owner_id,
            locked_at: row.locked_at,
            lease_expires_at: row.lease_expires_at,
            repo_id: row.repo_id,
            scope: row.scope,
        })
    }

    /// Admin/force release: delete regardless of owner.
    pub async fn delete_lock(
        &self,
        repo_id: &str,
        scope: &str,
        file_path: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            DELETE FROM locks
            WHERE repo_id = $1 AND scope = $2 AND file_path = $3
            "#,
        )
        .bind(repo_id)
        .bind(scope)
        .bind(file_path)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Owner-scoped release used by `unlock`/expired-renew cleanup: only removes
    /// the lock when it is still owned by `owner_id` in the database. Returns
    /// `false` when no such row exists (e.g. the lease expired and another
    /// principal re-acquired it), so we never delete a valid lock we no longer hold.
    pub async fn delete_lock_owned(
        &self,
        repo_id: &str,
        scope: &str,
        file_path: &str,
        owner_id: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM locks
            WHERE repo_id = $1 AND scope = $2 AND file_path = $3 AND owner_id = $4
            "#,
        )
        .bind(repo_id)
        .bind(scope)
        .bind(file_path)
        .bind(owner_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }
}
