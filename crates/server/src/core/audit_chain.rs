use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sqlx::{FromRow, PgPool, Postgres, QueryBuilder};

#[derive(Clone)]
pub struct AuditChain {
    pool: PgPool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditVerifyResult {
    pub valid: bool,
    pub checked: i64,
    pub broken_at_seq: Option<i64>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditChainEntry {
    pub seq: i64,
    pub prev_hash: String,
    pub entry_hash: String,
    pub action: String,
    pub actor_id: String,
    pub repo_id: Option<String>,
    pub target_id: Option<String>,
    pub payload: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct AuditRow {
    seq: i64,
    prev_hash: String,
    entry_hash: String,
    action: String,
    actor_id: String,
    repo_id: Option<String>,
    target_id: Option<String>,
    payload: Value,
    created_at: DateTime<Utc>,
}

impl AuditChain {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn append(
        &self,
        action: &str,
        actor_id: &str,
        repo_id: Option<&str>,
        target_id: Option<&str>,
        payload: Value,
    ) -> Result<String, sqlx::Error> {
        let mut tx = self.pool.begin().await?;

        // serialize append writes to avoid hash forks under concurrency
        sqlx::query("SELECT pg_advisory_xact_lock(92426001)")
            .execute(&mut *tx)
            .await?;

        let prev_hash = sqlx::query_scalar::<_, Option<String>>(
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

        let created_at = Utc::now();
        let payload_bytes = serde_json::to_vec(&payload).unwrap_or_default();
        let payload_hash = blake3::hash(&payload_bytes).to_hex().to_string();
        let material = format!(
            "{}|{}|{}|{}|{}|{}|{}",
            prev_hash,
            action,
            actor_id,
            repo_id.unwrap_or_default(),
            target_id.unwrap_or_default(),
            payload_hash,
            created_at.timestamp_millis()
        );
        let entry_hash = blake3::hash(material.as_bytes()).to_hex().to_string();

        sqlx::query(
            r#"
            INSERT INTO audit_chain_entries (
                prev_hash, entry_hash, action, actor_id, repo_id, target_id, payload, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(&prev_hash)
        .bind(&entry_hash)
        .bind(action)
        .bind(actor_id)
        .bind(repo_id)
        .bind(target_id)
        .bind(payload)
        .bind(created_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(entry_hash)
    }

    pub async fn verify_chain(&self) -> Result<AuditVerifyResult, sqlx::Error> {
        let rows = sqlx::query_as::<_, AuditRow>(
            r#"
            SELECT seq, prev_hash, entry_hash, action, actor_id, repo_id, target_id, payload, created_at
            FROM audit_chain_entries
            ORDER BY seq ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut expected_prev = "GENESIS".to_string();
        // Count verified rows directly rather than deriving from `seq`, which has
        // gaps whenever a BIGSERIAL value is consumed by a rolled-back append.
        let mut checked = 0i64;
        for row in &rows {
            if row.prev_hash != expected_prev {
                return Ok(AuditVerifyResult {
                    valid: false,
                    checked,
                    broken_at_seq: Some(row.seq),
                    reason: Some("prev_hash mismatch".to_string()),
                });
            }

            let payload_hash = blake3::hash(&serde_json::to_vec(&row.payload).unwrap_or_default())
                .to_hex()
                .to_string();
            let material = format!(
                "{}|{}|{}|{}|{}|{}|{}",
                row.prev_hash,
                row.action,
                row.actor_id,
                row.repo_id.as_deref().unwrap_or_default(),
                row.target_id.as_deref().unwrap_or_default(),
                payload_hash,
                row.created_at.timestamp_millis()
            );
            let expected_hash = blake3::hash(material.as_bytes()).to_hex().to_string();
            if row.entry_hash != expected_hash {
                return Ok(AuditVerifyResult {
                    valid: false,
                    checked,
                    broken_at_seq: Some(row.seq),
                    reason: Some("entry_hash mismatch".to_string()),
                });
            }

            expected_prev = row.entry_hash.clone();
            checked += 1;
        }

        Ok(AuditVerifyResult {
            valid: true,
            checked,
            broken_at_seq: None,
            reason: None,
        })
    }

    pub async fn list_entries(
        &self,
        limit: i64,
        before_seq: Option<i64>,
        action: Option<&str>,
        actor_id: Option<&str>,
    ) -> Result<Vec<AuditChainEntry>, sqlx::Error> {
        let safe_limit = limit.clamp(1, 2000);
        let mut builder = QueryBuilder::<Postgres>::new(
            "SELECT seq, prev_hash, entry_hash, action, actor_id, repo_id, target_id, payload, created_at FROM audit_chain_entries",
        );

        let mut has_where = false;
        if let Some(seq) = before_seq {
            builder.push(" WHERE seq < ");
            builder.push_bind(seq);
            has_where = true;
        }
        if let Some(action) = action {
            if has_where {
                builder.push(" AND ");
            } else {
                builder.push(" WHERE ");
                has_where = true;
            }
            builder.push("action = ");
            builder.push_bind(action);
        }
        if let Some(actor_id) = actor_id {
            if has_where {
                builder.push(" AND ");
            } else {
                builder.push(" WHERE ");
            }
            builder.push("actor_id = ");
            builder.push_bind(actor_id);
        }

        builder.push(" ORDER BY seq ASC LIMIT ");
        builder.push_bind(safe_limit);

        let rows = builder
            .build_query_as::<AuditRow>()
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|row| AuditChainEntry {
                seq: row.seq,
                prev_hash: row.prev_hash,
                entry_hash: row.entry_hash,
                action: row.action,
                actor_id: row.actor_id,
                repo_id: row.repo_id,
                target_id: row.target_id,
                payload: row.payload,
                created_at: row.created_at,
            })
            .collect())
    }
}
