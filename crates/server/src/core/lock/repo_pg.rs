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

    pub async fn upsert_lock(&self, lock: &FileLock) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO locks (file_path, owner_id, locked_at, lease_expires_at, force_released, repo_id, scope)
            VALUES ($1, $2, $3, $4, FALSE, $5, $6)
            ON CONFLICT (repo_id, scope, file_path)
            DO UPDATE SET
                owner_id = EXCLUDED.owner_id,
                locked_at = EXCLUDED.locked_at,
                lease_expires_at = EXCLUDED.lease_expires_at,
                force_released = FALSE
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
        Ok(())
    }

    pub async fn acquire_lock_atomic(&self, lock: &FileLock) -> Result<FileLock, sqlx::Error> {
        let row = sqlx::query_as::<_, LockRow>(
            r#"
            WITH attempted AS (
                INSERT INTO locks (file_path, owner_id, locked_at, lease_expires_at, force_released, repo_id, scope)
                VALUES ($1, $2, $3, $4, FALSE, $5, $6)
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
            FROM attempted
            UNION ALL
            SELECT file_path, owner_id, locked_at, lease_expires_at, repo_id, scope
            FROM current_lock
            WHERE NOT EXISTS (SELECT 1 FROM attempted)
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
}
