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
    pub fn from_env(pool: PgPool) -> Self {
        let required = std::env::var("HIGH_RISK_SIGNATURE_REQUIRED")
            .ok()
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let secret = std::env::var("HIGH_RISK_SIGNING_SECRET")
            .unwrap_or_else(|_| "hypertide-dev-signing-secret".to_string());
        let skew_secs = std::env::var("HIGH_RISK_SIG_SKEW_SECS")
            .ok()
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(300);
        Self {
            pool,
            required,
            secret,
            skew_secs,
        }
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
        let expected = blake3::hash(material.as_bytes()).to_hex().to_string();

        if expected != signature {
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

#[cfg(test)]
impl HighRiskGuard {
    /// 测试专用构造器，绕过环境变量读取
    fn new_for_test(pool: PgPool, required: bool, secret: &str, skew_secs: i64) -> Self {
        Self {
            pool,
            required,
            secret: secret.to_string(),
            skew_secs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};
    use sqlx::postgres::PgPoolOptions;

    const TEST_SECRET: &str = "test-signing-secret";

    /// 创建一个惰性连接池（不需要真实数据库连接即可创建）
    fn lazy_pool() -> PgPool {
        PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_secs(2))
            .connect_lazy("postgres://hypertide:hypertide@localhost/hypertide")
            .expect("lazy pool")
    }

    /// 根据 HighRiskGuard 的签名算法计算期望签名
    fn compute_signature(
        secret: &str,
        action: &str,
        actor_id: &str,
        nonce: &str,
        timestamp: i64,
        payload: &Value,
    ) -> String {
        let payload_hash = blake3::hash(
            serde_json::to_string(payload)
                .unwrap_or_default()
                .as_bytes(),
        )
        .to_hex()
        .to_string();
        let material = format!(
            "{}|{}|{}|{}|{}|{}",
            secret, action, actor_id, nonce, timestamp, payload_hash
        );
        blake3::hash(material.as_bytes()).to_hex().to_string()
    }

    /// 构造包含签名信息的请求头
    fn signed_headers(nonce: &str, timestamp: i64, signature: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("X-HT-Nonce", HeaderValue::from_str(nonce).unwrap());
        headers.insert(
            "X-HT-Timestamp",
            HeaderValue::from_str(&timestamp.to_string()).unwrap(),
        );
        headers.insert("X-HT-Signature", HeaderValue::from_str(signature).unwrap());
        headers
    }

    /// 测试1：有效签名通过验证（签名逻辑正确，数据库层可能报错）
    #[tokio::test]
    async fn valid_signature_passes_verification() {
        let guard = HighRiskGuard::new_for_test(lazy_pool(), true, TEST_SECRET, 300);
        let now = Utc::now().timestamp();
        let payload = serde_json::json!({"key": "value"});
        let sig = compute_signature(
            TEST_SECRET,
            "TEST_ACTION",
            "user-1",
            "nonce-001",
            now,
            &payload,
        );
        let headers = signed_headers("nonce-001", now, &sig);

        let result = guard
            .verify(&headers, "TEST_ACTION", "user-1", &payload)
            .await;

        // 签名验证通过后会尝试写入 nonce 表，惰性池无真实连接时返回数据库错误
        // 只要不是签名/时间戳相关错误，就说明签名逻辑正确
        assert!(
            result.is_ok()
                || result
                    .as_ref()
                    .unwrap_err()
                    .contains("failed to persist nonce"),
            "签名验证应通过，实际错误: {:?}",
            result
        );
    }

    /// 测试2：过期时间戳（超出偏移窗口）被拒绝
    #[tokio::test]
    async fn expired_timestamp_is_rejected() {
        let guard = HighRiskGuard::new_for_test(lazy_pool(), true, TEST_SECRET, 60);
        // 时间戳设置在偏移窗口之外（120秒前，超过60秒的窗口）
        let old_timestamp = Utc::now().timestamp() - 120;
        let payload = serde_json::json!({});
        let sig = compute_signature(
            TEST_SECRET,
            "TEST_ACTION",
            "user-1",
            "nonce-expired",
            old_timestamp,
            &payload,
        );
        let headers = signed_headers("nonce-expired", old_timestamp, &sig);

        let result = guard
            .verify(&headers, "TEST_ACTION", "user-1", &payload)
            .await;
        assert_eq!(result, Err("signature timestamp out of window".to_string()));
    }

    /// 测试3：Nonce 重放被拒绝（同一 nonce 使用两次）
    #[tokio::test]
    #[ignore = "需要真实数据库连接（high_risk_nonces 表）"]
    async fn nonce_replay_is_rejected() {
        let pool = PgPoolOptions::new()
            .connect("postgres://hypertide:hypertide@localhost/hypertide")
            .await
            .expect("需要数据库连接");
        let guard = HighRiskGuard::new_for_test(pool.clone(), true, TEST_SECRET, 300);
        let now = Utc::now().timestamp();
        let payload = serde_json::json!({"data": "test"});
        let nonce = "replay-test-nonce-001";
        let sig = compute_signature(TEST_SECRET, "TEST_ACTION", "user-1", nonce, now, &payload);
        let headers = signed_headers(nonce, now, &sig);

        // 第一次调用应成功
        let first = guard
            .verify(&headers, "TEST_ACTION", "user-1", &payload)
            .await;
        assert!(first.is_ok(), "首次验证应成功: {:?}", first);

        // 第二次使用相同 nonce 应被拒绝
        let second = guard
            .verify(&headers, "TEST_ACTION", "user-1", &payload)
            .await;
        assert_eq!(second, Err("nonce replay detected".to_string()));
    }

    /// 测试4：缺少必需请求头被拒绝
    #[tokio::test]
    async fn missing_required_headers_is_rejected() {
        let guard = HighRiskGuard::new_for_test(lazy_pool(), true, TEST_SECRET, 300);
        let payload = serde_json::json!({});

        // 缺少所有头部
        let empty_headers = HeaderMap::new();
        let result = guard
            .verify(&empty_headers, "TEST_ACTION", "user-1", &payload)
            .await;
        assert_eq!(result, Err("missing X-HT-Nonce".to_string()));

        // 只有 Nonce，缺少 Timestamp
        let mut headers = HeaderMap::new();
        headers.insert("X-HT-Nonce", HeaderValue::from_str("n1").unwrap());
        let result = guard
            .verify(&headers, "TEST_ACTION", "user-1", &payload)
            .await;
        assert_eq!(result, Err("missing X-HT-Timestamp".to_string()));

        // 有 Nonce 和 Timestamp，缺少 Signature
        headers.insert(
            "X-HT-Timestamp",
            HeaderValue::from_str(&Utc::now().timestamp().to_string()).unwrap(),
        );
        let result = guard
            .verify(&headers, "TEST_ACTION", "user-1", &payload)
            .await;
        assert_eq!(result, Err("missing X-HT-Signature".to_string()));
    }

    /// 测试5：无效签名（错误密钥）被拒绝
    #[tokio::test]
    async fn invalid_signature_wrong_secret_is_rejected() {
        let guard = HighRiskGuard::new_for_test(lazy_pool(), true, TEST_SECRET, 300);
        let now = Utc::now().timestamp();
        let payload = serde_json::json!({"key": "value"});

        // 使用错误的密钥计算签名
        let wrong_sig = compute_signature(
            "wrong-secret",
            "TEST_ACTION",
            "user-1",
            "nonce-999",
            now,
            &payload,
        );
        let headers = signed_headers("nonce-999", now, &wrong_sig);

        let result = guard
            .verify(&headers, "TEST_ACTION", "user-1", &payload)
            .await;
        assert_eq!(result, Err("invalid signature".to_string()));
    }
}
