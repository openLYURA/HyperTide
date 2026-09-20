use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use std::collections::HashSet;

use crate::core::checkpoint::CheckpointRecord;

#[derive(Debug, Clone, Deserialize)]
struct WitnessKey {
    id: String,
    secret: String,
    #[serde(default = "default_witness_scope")]
    scope: String,
    #[serde(default = "default_witness_environment")]
    environment: String,
}

#[derive(Debug, Clone, Deserialize)]
struct WitnessConfig {
    witnesses: Vec<WitnessKey>,
    quorum: Option<usize>,
    scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct WitnessReceipt {
    pub checkpoint_id: String,
    pub witness_id: String,
    pub signature: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WitnessSummary {
    pub checkpoint_id: String,
    pub receipts: Vec<WitnessReceipt>,
    pub quorum: usize,
    pub quorum_met: bool,
    pub distinct_scopes: Vec<String>,
    pub cross_scope_quorum_met: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct WitnessScopeEntry {
    pub witness_id: String,
    pub scope: String,
    pub environment: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WitnessEnvironmentEntry {
    pub environment: String,
    pub witness_ids: Vec<String>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WitnessTopology {
    pub scope: String,
    pub witness_ids: Vec<String>,
    pub witness_scopes: Vec<WitnessScopeEntry>,
    pub environments: Vec<WitnessEnvironmentEntry>,
    pub quorum: usize,
    pub cross_environment: bool,
    pub cross_environment_quorum_possible: bool,
}

#[derive(Clone)]
pub struct WitnessService {
    pool: PgPool,
    witnesses: Vec<WitnessKey>,
    quorum: usize,
    scope: String,
}

impl WitnessService {
    pub fn from_env(pool: PgPool) -> Self {
        let structured_config = load_structured_witness_config();
        let configured = std::env::var("WITNESS_KEYS").ok();
        let default_scope =
            std::env::var("WITNESS_DEFAULT_SCOPE").unwrap_or_else(|_| "local".to_string());
        let default_environment =
            std::env::var("WITNESS_DEFAULT_ENVIRONMENT").unwrap_or_else(|_| "local".to_string());
        let mut witnesses = structured_config
            .as_ref()
            .map(|config| normalize_structured_witnesses(config.witnesses.clone()))
            .unwrap_or_else(|| {
                parse_legacy_witness_keys(
                    configured.as_deref(),
                    &default_scope,
                    &default_environment,
                )
            });
        if witnesses.is_empty() {
            witnesses = vec![
                WitnessKey {
                    id: "witness-a".to_string(),
                    secret: "dev-secret-a".to_string(),
                    scope: default_scope.clone(),
                    environment: default_environment.clone(),
                },
                WitnessKey {
                    id: "witness-b".to_string(),
                    secret: "dev-secret-b".to_string(),
                    scope: default_scope.clone(),
                    environment: default_environment.clone(),
                },
                WitnessKey {
                    id: "witness-c".to_string(),
                    secret: "dev-secret-c".to_string(),
                    scope: default_scope,
                    environment: default_environment,
                },
            ];
        }

        let quorum = structured_config
            .as_ref()
            .and_then(|config| config.quorum)
            .or_else(|| {
                std::env::var("WITNESS_QUORUM")
                    .ok()
                    .and_then(|v| v.parse::<usize>().ok())
            })
            .unwrap_or(2)
            .clamp(1, witnesses.len());
        let scope = structured_config
            .and_then(|config| config.scope)
            .filter(|value| !value.trim().is_empty())
            .or_else(|| std::env::var("WITNESS_SCOPE").ok())
            .unwrap_or_else(|| "single-env".to_string());

        Self {
            pool,
            witnesses,
            quorum,
            scope,
        }
    }

    pub async fn attest(
        &self,
        checkpoint_id: &str,
        witness_id: Option<&str>,
    ) -> Result<WitnessReceipt, String> {
        let checkpoint = sqlx::query_as::<_, CheckpointRecord>(
            r#"
            SELECT checkpoint_id, log_head_hash, log_size, state_root, created_at
            FROM trust_checkpoints
            WHERE checkpoint_id = $1
            "#,
        )
        .bind(checkpoint_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| format!("failed to query checkpoint: {error}"))?
        .ok_or_else(|| "checkpoint not found".to_string())?;

        let witness = match witness_id {
            Some(id) => self
                .witnesses
                .iter()
                .find(|w| w.id == id)
                .ok_or_else(|| "witness_id not configured".to_string())?,
            None => self
                .witnesses
                .first()
                .ok_or_else(|| "no witness configured".to_string())?,
        };

        let material = format!(
            "{}|{}|{}|{}",
            checkpoint.checkpoint_id,
            checkpoint.log_head_hash,
            checkpoint.log_size,
            checkpoint.state_root
        );
        let signature = {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;
            type HmacSha256 = Hmac<Sha256>;

            let mut mac = HmacSha256::new_from_slice(witness.secret.as_bytes())
                .expect("HMAC accepts any key length");
            mac.update(material.as_bytes());
            hex::encode(mac.finalize().into_bytes())
        };
        let created_at = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO witness_receipts (checkpoint_id, witness_id, signature, created_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (checkpoint_id, witness_id)
            DO UPDATE SET signature = EXCLUDED.signature, created_at = EXCLUDED.created_at
            "#,
        )
        .bind(checkpoint_id)
        .bind(&witness.id)
        .bind(&signature)
        .bind(created_at)
        .execute(&self.pool)
        .await
        .map_err(|error| format!("failed to persist witness receipt: {error}"))?;

        Ok(WitnessReceipt {
            checkpoint_id: checkpoint_id.to_string(),
            witness_id: witness.id.clone(),
            signature,
            created_at,
        })
    }

    /// Recompute a receipt's HMAC over the referenced checkpoint material and
    /// verify it in constant time. Returns false for receipts from unconfigured
    /// witnesses or with a malformed/invalid signature, so forged rows cannot count.
    fn verify_receipt_signature(
        &self,
        checkpoint: &CheckpointRecord,
        receipt: &WitnessReceipt,
    ) -> bool {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let Some(witness) = self.witnesses.iter().find(|w| w.id == receipt.witness_id) else {
            return false;
        };
        let Ok(provided) = hex::decode(&receipt.signature) else {
            return false;
        };
        let material = format!(
            "{}|{}|{}|{}",
            checkpoint.checkpoint_id,
            checkpoint.log_head_hash,
            checkpoint.log_size,
            checkpoint.state_root
        );
        let Ok(mut mac) = HmacSha256::new_from_slice(witness.secret.as_bytes()) else {
            return false;
        };
        mac.update(material.as_bytes());
        mac.verify_slice(&provided).is_ok()
    }

    pub async fn summary(&self, checkpoint_id: &str) -> Result<WitnessSummary, String> {
        let receipts = sqlx::query_as::<_, WitnessReceipt>(
            r#"
            SELECT checkpoint_id, witness_id, signature, created_at
            FROM witness_receipts
            WHERE checkpoint_id = $1
            ORDER BY created_at ASC
            "#,
        )
        .bind(checkpoint_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| format!("failed to query witness receipts: {error}"))?;

        // Quorum must be established by cryptographically verified receipts from
        // configured witnesses, not by counting rows: a DB-write attacker could
        // otherwise insert junk receipts to fake a quorum. Fetch the referenced
        // checkpoint and re-verify each receipt's signature against its material.
        let checkpoint = sqlx::query_as::<_, CheckpointRecord>(
            r#"
            SELECT checkpoint_id, log_head_hash, log_size, state_root, created_at
            FROM trust_checkpoints
            WHERE checkpoint_id = $1
            "#,
        )
        .bind(checkpoint_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| format!("failed to query checkpoint: {error}"))?;

        let mut verified_witnesses = HashSet::new();
        let mut scopes = HashSet::new();
        if let Some(checkpoint) = &checkpoint {
            for receipt in &receipts {
                if !self.verify_receipt_signature(checkpoint, receipt) {
                    continue;
                }
                verified_witnesses.insert(receipt.witness_id.clone());
                if let Some(scope) = self
                    .witnesses
                    .iter()
                    .find(|w| w.id == receipt.witness_id)
                    .map(|w| w.scope.clone())
                {
                    scopes.insert(scope);
                }
            }
        }
        let mut distinct_scopes = scopes.into_iter().collect::<Vec<_>>();
        distinct_scopes.sort();

        let quorum_met = verified_witnesses.len() >= self.quorum;
        Ok(WitnessSummary {
            checkpoint_id: checkpoint_id.to_string(),
            quorum: self.quorum,
            quorum_met,
            cross_scope_quorum_met: quorum_met && distinct_scopes.len() >= 2,
            distinct_scopes,
            receipts,
        })
    }

    pub fn topology(&self) -> WitnessTopology {
        let mut environments = self.witnesses.iter().fold(
            Vec::<WitnessEnvironmentEntry>::new(),
            |mut entries, witness| {
                if let Some(entry) = entries
                    .iter_mut()
                    .find(|entry| entry.environment == witness.environment)
                {
                    entry.witness_ids.push(witness.id.clone());
                    if !entry.scopes.iter().any(|scope| scope == &witness.scope) {
                        entry.scopes.push(witness.scope.clone());
                    }
                } else {
                    entries.push(WitnessEnvironmentEntry {
                        environment: witness.environment.clone(),
                        witness_ids: vec![witness.id.clone()],
                        scopes: vec![witness.scope.clone()],
                    });
                }
                entries
            },
        );
        environments.sort_by(|left, right| left.environment.cmp(&right.environment));
        for entry in &mut environments {
            entry.witness_ids.sort();
            entry.scopes.sort();
        }

        let cross_environment = environments.len() >= 2;
        WitnessTopology {
            scope: self.scope.clone(),
            witness_ids: self.witnesses.iter().map(|w| w.id.clone()).collect(),
            witness_scopes: self
                .witnesses
                .iter()
                .map(|w| WitnessScopeEntry {
                    witness_id: w.id.clone(),
                    scope: w.scope.clone(),
                    environment: w.environment.clone(),
                })
                .collect(),
            environments,
            quorum: self.quorum,
            cross_environment,
            cross_environment_quorum_possible: cross_environment
                && self.quorum >= 2
                && self.witnesses.len() >= self.quorum,
        }
    }
}

fn default_witness_scope() -> String {
    "local".to_string()
}

fn default_witness_environment() -> String {
    "local".to_string()
}

fn load_structured_witness_config() -> Option<WitnessConfig> {
    let raw = std::env::var("WITNESS_CONFIG_JSON").ok().or_else(|| {
        std::env::var("WITNESS_CONFIG_FILE")
            .ok()
            .and_then(|path| std::fs::read_to_string(path).ok())
    })?;
    serde_json::from_str::<WitnessConfig>(&raw)
        .map_err(|error| {
            tracing::warn!("Ignoring invalid structured witness config: {error}");
            error
        })
        .ok()
}

fn normalize_structured_witnesses(witnesses: Vec<WitnessKey>) -> Vec<WitnessKey> {
    witnesses
        .into_iter()
        .filter(|witness| !witness.id.trim().is_empty() && !witness.secret.trim().is_empty())
        .map(|mut witness| {
            witness.id = witness.id.trim().to_string();
            witness.secret = witness.secret.trim().to_string();
            witness.scope = witness.scope.trim().to_string();
            witness.environment = witness.environment.trim().to_string();
            if witness.scope.is_empty() {
                witness.scope = default_witness_scope();
            }
            if witness.environment.is_empty() {
                witness.environment = default_witness_environment();
            }
            witness
        })
        .collect()
}

fn parse_legacy_witness_keys(
    configured: Option<&str>,
    default_scope: &str,
    default_environment: &str,
) -> Vec<WitnessKey> {
    let Some(configured) = configured else {
        return Vec::new();
    };
    configured
        .split(',')
        .filter_map(|item| {
            let mut parts = item.splitn(4, ':');
            let id = parts.next()?.trim();
            let secret = parts.next()?.trim();
            let scope = parts
                .next()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| default_scope.to_string());
            let environment = parts
                .next()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| default_environment.to_string());
            if id.is_empty() || secret.is_empty() {
                return None;
            }
            Some(WitnessKey {
                id: id.to_string(),
                secret: secret.to_string(),
                scope,
                environment,
            })
        })
        .collect()
}
