use chrono::{Duration, Utc};
use serde_json::Value;
use sqlx::PgPool;

#[derive(Clone)]
pub struct HighRiskGuard {
    pool: PgPool,
    required: bool,
    secret: String,
    skew_secs: i64,
}

impl HighRiskGuard {
    pub fn from_env(pool: PgPool) -> Result<Self, String> {
        let required = std::env::var("HIGH_RISK_SIGNATURE_REQUIRED")
            .ok()
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        // Fail closed: never fall back to a hardcoded/shipped signing secret when
        // enforcement is on. A default secret in open-source code would let anyone
        // forge a valid X-HT-Signature and defeat the step-up check entirely.
        let secret = std::env::var("HIGH_RISK_SIGNING_SECRET")
            .ok()
            .filter(|value| !value.trim().is_empty());
        if required && secret.is_none() {
            return Err(
                "HIGH_RISK_SIGNATURE_REQUIRED is enabled but HIGH_RISK_SIGNING_SECRET is unset \
                 or empty; refusing to start with an insecure default signing secret"
                    .to_string(),
            );
        }
        let secret = secret.unwrap_or_default();
        let skew_secs = std::env::var("HIGH_RISK_SIG_SKEW_SECS")
            .ok()
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(300);
        Ok(Self {
            pool,
            required,
            secret,
            skew_secs,
        })
    }

    pub async fn verify(
        &self,
        headers: &axum::http::HeaderMap,
        action: &str,
        actor_id: &str,
        payload: &Value,
    ) -> Result<(), String> {
        if !self.required {
            return Ok(());
        }

        let nonce = headers
            .get("X-HT-Nonce")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| "missing X-HT-Nonce".to_string())?;
        let timestamp = headers
            .get("X-HT-Timestamp")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| "missing X-HT-Timestamp".to_string())?
            .parse::<i64>()
            .map_err(|_| "invalid X-HT-Timestamp".to_string())?;
        let signature = headers
            .get("X-HT-Signature")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| "missing X-HT-Signature".to_string())?;

        let now = Utc::now().timestamp();
        if (now - timestamp).abs() > self.skew_secs {
            return Err("signature timestamp out of window".to_string());
        }

        let payload_hash = blake3::hash(
            serde_json::to_string(payload)
                .unwrap_or_default()
                .as_bytes(),
        )
        .to_hex()
        .to_string();
        let material = format!(
            "{}|{}|{}|{}|{}|{}",
            self.secret, action, actor_id, nonce, timestamp, payload_hash
        );
        let expected = blake3::hash(material.as_bytes());
        // Parse the client signature into a fixed 32-byte digest and compare with
        // blake3::Hash's constant-time equality, avoiding a byte-by-byte timing
        // oracle on the expected MAC.
        let provided = match blake3::Hash::from_hex(signature) {
            Ok(hash) => hash,
            Err(_) => return Err("invalid signature".to_string()),
        };
        if expected != provided {
            return Err("invalid signature".to_string());
        }

        let expires_at = Utc::now() + Duration::seconds(self.skew_secs.max(30));
        let _ = sqlx::query("DELETE FROM high_risk_nonces WHERE expires_at <= NOW()")
            .execute(&self.pool)
            .await;
        let inserted = sqlx::query(
            r#"
            INSERT INTO high_risk_nonces (nonce, action, actor_id, expires_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (nonce) DO NOTHING
            "#,
        )
        .bind(nonce)
        .bind(action)
        .bind(actor_id)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|error| format!("failed to persist nonce: {error}"))?;
        if inserted.rows_affected() == 0 {
            return Err("nonce replay detected".to_string());
        }

        Ok(())
    }
}
