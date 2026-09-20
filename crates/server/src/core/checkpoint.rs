use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct CheckpointRecord {
    pub checkpoint_id: String,
    pub log_head_hash: String,
    pub log_size: i64,
    pub state_root: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct CheckpointService {
    pool: PgPool,
}

impl CheckpointService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn generate_checkpoint(&self) -> Result<CheckpointRecord, sqlx::Error> {
        // Take a consistent point-in-time snapshot: run every read inside one
        // REPEATABLE READ transaction and hold the same advisory lock the audit
        // appender uses, so log_head/log_size and the table counts can't describe
        // different moments (a TOCTOU that witnesses would then attest).
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT pg_advisory_xact_lock(92426001)")
            .execute(&mut *tx)
            .await?;

        let log_head_hash = sqlx::query_scalar::<_, Option<String>>(
            r#"
            SELECT entry_hash
            FROM audit_chain_entries
            ORDER BY seq DESC
            LIMIT 1
            "#,
        )
        .fetch_one(&mut *tx)
        .await?
        .unwrap_or_else(|| "GENESIS".to_string());

        let log_size = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_chain_entries")
            .fetch_one(&mut *tx)
            .await?;

        let locks_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM locks WHERE force_released = FALSE")
                .fetch_one(&mut *tx)
                .await
                .unwrap_or(0);
        let changesets_count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM changesets")
            .fetch_one(&mut *tx)
            .await
            .unwrap_or(0);
        let manifests_count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM manifests")
            .fetch_one(&mut *tx)
            .await
            .unwrap_or(0);
        let chunks_count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM chunks")
            .fetch_one(&mut *tx)
            .await
            .unwrap_or(0);

        let state_payload = json!({
            "locks_count": locks_count,
            "changesets_count": changesets_count,
            "manifests_count": manifests_count,
            "chunks_count": chunks_count,
            "log_head_hash": log_head_hash,
            "log_size": log_size,
        });
        let state_root = blake3::hash(
            serde_json::to_string(&state_payload)
                .unwrap_or_default()
                .as_bytes(),
        )
        .to_hex()
        .to_string();

        let checkpoint = CheckpointRecord {
            checkpoint_id: Uuid::new_v4().to_string(),
            log_head_hash,
            log_size,
            state_root,
            created_at: Utc::now(),
        };

        sqlx::query(
            r#"
            INSERT INTO trust_checkpoints (checkpoint_id, log_head_hash, log_size, state_root, created_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(&checkpoint.checkpoint_id)
        .bind(&checkpoint.log_head_hash)
        .bind(checkpoint.log_size)
        .bind(&checkpoint.state_root)
        .bind(checkpoint.created_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(checkpoint)
    }

    pub async fn latest_checkpoint(&self) -> Result<Option<CheckpointRecord>, sqlx::Error> {
        sqlx::query_as::<_, CheckpointRecord>(
            r#"
            SELECT checkpoint_id, log_head_hash, log_size, state_root, created_at
            FROM trust_checkpoints
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .fetch_optional(&self.pool)
        .await
    }
}
