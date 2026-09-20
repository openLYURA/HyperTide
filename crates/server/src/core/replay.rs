use serde::Serialize;
use serde_json::Value;
use sqlx::PgPool;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Default)]
pub struct ReplaySummary {
    pub events_processed: i64,
    pub lock_acquired: i64,
    pub lock_released: i64,
    pub changeset_visible: i64,
    pub changeset_approved: i64,
    pub changeset_promoted: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReplayVerification {
    pub summary: ReplaySummary,
    pub current_locks: i64,
    pub current_visible_changesets: i64,
    pub branch_heads_in_replay: usize,
    pub consistency_ok: bool,
    pub mismatches: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReplayReadinessMetrics {
    pub events_processed: i64,
    pub replay_mismatch_count: usize,
    pub audit_entry_count: i64,
    pub checkpoint_count: i64,
    pub witness_receipt_count: i64,
    pub branch_heads_in_db: i64,
    pub branch_heads_in_replay: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReplayReadinessReport {
    pub consistency_ok: bool,
    pub recommendation: String,
    pub blockers: Vec<String>,
    pub metrics: ReplayReadinessMetrics,
}

#[derive(Clone)]
pub struct ReplayService {
    pool: PgPool,
}

#[derive(Debug, sqlx::FromRow)]
struct EventRow {
    #[expect(dead_code)]
    event_id: i64,
    event_type: String,
    payload: Value,
    repo_id: Option<String>,
    changeset_id: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct BranchHeadRow {
    repo_id: String,
    branch_name: String,
    head_changeset_id: String,
}

#[derive(Debug, Default)]
struct ReplayAccumulator {
    summary: ReplaySummary,
    current_locks: HashSet<String>,
    current_visible_changesets: HashSet<String>,
    branch_heads: HashMap<String, String>,
}

impl ReplayAccumulator {
    fn apply_event(
        &mut self,
        event_type: &str,
        payload: Option<&Value>,
        changeset_id: Option<&str>,
        repo_id: Option<&str>,
    ) {
        self.summary.events_processed += 1;
        match event_type {
            "LOCK_ACQUIRED" => {
                self.summary.lock_acquired += 1;
                if let Some(path) = extract_file_path(payload) {
                    self.current_locks.insert(lock_key(repo_id, path));
                }
            }
            "LOCK_RELEASED" | "LOCK_FORCE_RELEASED" => {
                self.summary.lock_released += 1;
                if let Some(path) = extract_file_path(payload) {
                    self.current_locks.remove(&lock_key(repo_id, path));
                }
            }
            "CHANGESET_VISIBLE" | "ROLLBACK_VISIBLE" => {
                self.summary.changeset_visible += 1;
                if let Some(id) = changeset_id {
                    self.current_visible_changesets.insert(id.to_string());
                }
                self.update_branch_head(payload, changeset_id, repo_id);
            }
            "CHANGESET_APPROVED" => {
                self.summary.changeset_approved += 1;
            }
            "CHANGESET_PROMOTED" => {
                self.summary.changeset_promoted += 1;
                if let Some(id) = changeset_id {
                    self.current_visible_changesets.insert(id.to_string());
                }
                self.update_branch_head(payload, changeset_id, repo_id);
            }
            _ => {}
        }
    }

    fn update_branch_head(
        &mut self,
        payload: Option<&Value>,
        changeset_id: Option<&str>,
        repo_id: Option<&str>,
    ) {
        let Some(repo) = repo_id else {
            return;
        };
        let Some(branch) = extract_branch(payload) else {
            return;
        };
        let Some(changeset_id) = changeset_id else {
            return;
        };
        self.branch_heads
            .insert(branch_head_key(repo, branch), changeset_id.to_string());
    }
}

fn extract_file_path(payload: Option<&Value>) -> Option<&str> {
    payload?.get("file_path")?.as_str()
}

/// Key locks by `(repo_id, file_path)` to mirror the DB's uniqueness. Keying by
/// path alone collapsed identical paths across repos into one replay entry,
/// producing a false mismatch against `SELECT COUNT(*) FROM locks`.
fn lock_key(repo_id: Option<&str>, path: &str) -> String {
    format!("{}::{}", repo_id.unwrap_or(""), path)
}

fn extract_branch(payload: Option<&Value>) -> Option<&str> {
    payload?.get("branch")?.as_str()
}

fn branch_head_key(repo_id: &str, branch: &str) -> String {
    format!("{repo_id}::{branch}")
}

impl ReplayService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn verify(&self) -> Result<ReplayVerification, sqlx::Error> {
        self.verify_incremental(None).await
    }

    /// Save a replay checkpoint marking the current event sequence position.
    pub async fn save_checkpoint(&self, checkpoint_id: &str) -> Result<(), sqlx::Error> {
        let max_seq: Option<i64> = sqlx::query_scalar("SELECT MAX(event_id) FROM event_store")
            .fetch_one(&self.pool)
            .await?;
        let event_seq = max_seq.unwrap_or(0);
        sqlx::query(
            r#"
            INSERT INTO replay_checkpoints (checkpoint_id, event_seq)
            VALUES ($1, $2)
            ON CONFLICT (checkpoint_id) DO UPDATE SET event_seq = EXCLUDED.event_seq
            "#,
        )
        .bind(checkpoint_id)
        .bind(event_seq)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Verify replay from an optional checkpoint. If `from_checkpoint` is None, does a full scan.
    pub async fn verify_incremental(
        &self,
        from_checkpoint: Option<&str>,
    ) -> Result<ReplayVerification, sqlx::Error> {
        // Always replay from the beginning. `replay_checkpoints` records only an
        // `event_seq` marker with no accumulated state snapshot, so replaying just
        // the suffix after a checkpoint into a fresh accumulator cannot reproduce
        // full state and would report spurious mismatches against the absolute DB
        // counts below. We still validate the checkpoint exists to preserve the
        // API contract, but a correct result requires a full scan.
        if let Some(cp_id) = from_checkpoint {
            let seq: Option<i64> = sqlx::query_scalar(
                "SELECT event_seq FROM replay_checkpoints WHERE checkpoint_id = $1",
            )
            .bind(cp_id)
            .fetch_optional(&self.pool)
            .await?;
            if seq.is_none() {
                return Err(sqlx::Error::RowNotFound);
            }
        }
        let start_seq = 0i64;

        let events = sqlx::query_as::<_, EventRow>(
            r#"
            SELECT event_id, event_type, payload, repo_id, changeset_id
            FROM event_store
            WHERE event_id > $1
            ORDER BY event_id ASC
            "#,
        )
        .bind(start_seq)
        .fetch_all(&self.pool)
        .await?;

        let mut replay = ReplayAccumulator::default();
        for event in &events {
            replay.apply_event(
                &event.event_type,
                Some(&event.payload),
                event.changeset_id.as_deref(),
                event.repo_id.as_deref(),
            );
        }

        let current_locks =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM locks WHERE force_released = FALSE")
                .fetch_one(&self.pool)
                .await?;
        let current_visible_changesets = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM changesets WHERE status = 'visible'",
        )
        .fetch_one(&self.pool)
        .await?;

        let mut mismatches = Vec::new();
        if replay.current_locks.len() as i64 != current_locks {
            mismatches.push(format!(
                "locks mismatch: replay_current={}, current={}",
                replay.current_locks.len(),
                current_locks
            ));
        }
        if replay.current_visible_changesets.len() as i64 != current_visible_changesets {
            mismatches.push(format!(
                "visible changesets mismatch: replay_current={}, current_visible_changesets={}",
                replay.current_visible_changesets.len(),
                current_visible_changesets
            ));
        }

        let branch_rows = sqlx::query_as::<_, BranchHeadRow>(
            r#"
            SELECT repo_id, branch_name, head_changeset_id
            FROM branches
            WHERE head_changeset_id IS NOT NULL
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        let mut db_heads = HashMap::new();
        for row in branch_rows {
            let key = branch_head_key(&row.repo_id, &row.branch_name);
            db_heads.insert(key, row.head_changeset_id);
        }
        for (key, db_head) in &db_heads {
            match replay.branch_heads.get(key) {
                Some(replay_head) if replay_head == db_head => {}
                Some(replay_head) => mismatches.push(format!(
                    "branch head mismatch for {key}: replay_head={replay_head}, db_head={db_head}"
                )),
                None => mismatches.push(format!(
                    "branch head missing in replay for {key}: db_head={db_head}"
                )),
            }
        }
        for (key, replay_head) in &replay.branch_heads {
            if !db_heads.contains_key(key) {
                mismatches.push(format!(
                    "branch head missing in db for {key}: replay_head={replay_head}"
                ));
            }
        }

        Ok(ReplayVerification {
            summary: replay.summary,
            current_locks,
            current_visible_changesets,
            branch_heads_in_replay: replay.branch_heads.len(),
            consistency_ok: mismatches.is_empty(),
            mismatches,
        })
    }

    pub async fn readiness(&self) -> Result<ReplayReadinessReport, sqlx::Error> {
        let verification = self.verify().await?;
        let audit_entry_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_chain_entries")
                .fetch_one(&self.pool)
                .await?;
        let checkpoint_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM trust_checkpoints")
                .fetch_one(&self.pool)
                .await?;
        let witness_receipt_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM witness_receipts")
                .fetch_one(&self.pool)
                .await?;
        let branch_heads_in_db = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM branches WHERE head_changeset_id IS NOT NULL",
        )
        .fetch_one(&self.pool)
        .await?;

        let mut blockers = Vec::new();
        if !verification.consistency_ok {
            blockers.push("replay consistency check has mismatches".to_string());
        }
        if verification.summary.events_processed == 0 {
            blockers.push("event store has no events".to_string());
        }
        if audit_entry_count == 0 {
            blockers.push("audit chain is empty".to_string());
        }
        if checkpoint_count == 0 {
            blockers.push("no trust checkpoint generated".to_string());
        }
        if branch_heads_in_db > 0 && verification.summary.changeset_promoted == 0 {
            blockers.push("no promote events found for branch head movement".to_string());
        }

        let recommendation = if blockers.is_empty() {
            "canary_event_led_candidate".to_string()
        } else {
            "keep_dual_write".to_string()
        };

        Ok(ReplayReadinessReport {
            consistency_ok: blockers.is_empty(),
            recommendation,
            blockers,
            metrics: ReplayReadinessMetrics {
                events_processed: verification.summary.events_processed,
                replay_mismatch_count: verification.mismatches.len(),
                audit_entry_count,
                checkpoint_count,
                witness_receipt_count,
                branch_heads_in_db,
                branch_heads_in_replay: verification.branch_heads_in_replay,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::ReplayAccumulator;
    use serde_json::json;

    #[test]
    fn rebuilds_lock_state_from_event_payloads() {
        let mut acc = ReplayAccumulator::default();

        acc.apply_event(
            "LOCK_ACQUIRED",
            Some(&json!({ "file_path": "assets/a.uasset" })),
            None,
            None,
        );
        acc.apply_event(
            "LOCK_RENEWED",
            Some(&json!({ "file_path": "assets/a.uasset" })),
            None,
            None,
        );
        acc.apply_event(
            "LOCK_RELEASED",
            Some(&json!({ "file_path": "assets/a.uasset" })),
            None,
            None,
        );

        assert_eq!(acc.current_locks.len(), 0);
        assert_eq!(acc.summary.lock_acquired, 1);
        assert_eq!(acc.summary.lock_released, 1);
    }

    #[test]
    fn rebuilds_visible_changeset_state_from_events() {
        let mut acc = ReplayAccumulator::default();

        acc.apply_event(
            "CHANGESET_VISIBLE",
            Some(&json!({})),
            Some("cs_visible"),
            None,
        );
        acc.apply_event(
            "CHANGESET_APPROVED",
            Some(&json!({})),
            Some("cs_draft"),
            None,
        );
        acc.apply_event(
            "CHANGESET_PROMOTED",
            Some(&json!({})),
            Some("cs_promoted"),
            None,
        );
        acc.apply_event(
            "ROLLBACK_VISIBLE",
            Some(&json!({})),
            Some("cs_rollback"),
            None,
        );

        assert_eq!(acc.current_visible_changesets.len(), 3);
        assert_eq!(acc.summary.changeset_visible, 2);
        assert_eq!(acc.summary.changeset_approved, 1);
        assert_eq!(acc.summary.changeset_promoted, 1);
    }

    #[test]
    fn tracks_latest_branch_head_from_visible_events() {
        let mut acc = ReplayAccumulator::default();

        acc.apply_event(
            "CHANGESET_VISIBLE",
            Some(&json!({ "branch": "main" })),
            Some("cs1"),
            Some("repo-a"),
        );
        acc.apply_event(
            "CHANGESET_PROMOTED",
            Some(&json!({ "branch": "main" })),
            Some("cs2"),
            Some("repo-a"),
        );

        assert_eq!(
            acc.branch_heads.get("repo-a::main"),
            Some(&"cs2".to_string())
        );
    }
}
