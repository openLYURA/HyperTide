use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{FromRow, PgPool};

use crate::core::auth::Permission;

#[derive(Debug, Clone)]
pub struct StoredApiKey {
    pub owner_id: String,
    pub permissions: Vec<Permission>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked: bool,
}

#[derive(Debug, Clone)]
pub struct StoredRefreshToken {
    pub family_id: String,
    pub replaced_by_token_hash: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Clone)]
pub struct AuthRepo {
    pool: PgPool,
    pepper: String,
}

#[derive(Debug, FromRow)]
struct ApiKeyRow {
    principal_id: String,
    permissions: Value,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, FromRow)]
struct ApiKeyListRow {
    key_hash: String,
    principal_id: String,
    permissions: Value,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, FromRow)]
struct RefreshTokenRow {
    family_id: String,
    replaced_by_token_hash: Option<String>,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

impl AuthRepo {
    pub fn new(pool: PgPool, pepper: impl Into<String>) -> Self {
        Self {
            pool,
            pepper: pepper.into(),
        }
    }

    fn hash_secret(&self, raw: &str) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.pepper.as_bytes());
        hasher.update(b":");
        hasher.update(raw.as_bytes());
        hasher.finalize().to_hex().to_string()
    }

    fn permissions_to_json(permissions: &[Permission]) -> Value {
        let values = permissions
            .iter()
            .map(|perm| Value::String(perm.as_str().to_string()))
            .collect::<Vec<_>>();
        Value::Array(values)
    }

    fn permissions_from_json(value: Value) -> Vec<Permission> {
        value
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str())
                    .filter_map(Permission::from_str)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    }

    pub async fn upsert_api_key(
        &self,
        raw_key: &str,
        principal_id: &str,
        permissions: &[Permission],
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<(), sqlx::Error> {
        let key_hash = self.hash_secret(raw_key);
        let permissions_json = Self::permissions_to_json(permissions);

        sqlx::query(
            r#"
            INSERT INTO principals (principal_id, principal_type, display_name, disabled)
            VALUES ($1, 'service', $1, false)
            ON CONFLICT (principal_id) DO NOTHING
            "#,
        )
        .bind(principal_id)
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO api_keys (key_hash, principal_id, permissions, expires_at, revoked_at)
            VALUES ($1, $2, $3, $4, NULL)
            ON CONFLICT (key_hash)
            DO UPDATE SET
                principal_id = EXCLUDED.principal_id,
                permissions = EXCLUDED.permissions,
                expires_at = EXCLUDED.expires_at,
                revoked_at = NULL
            "#,
        )
        .bind(key_hash)
        .bind(principal_id)
        .bind(permissions_json)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn find_api_key(&self, raw_key: &str) -> Result<Option<StoredApiKey>, sqlx::Error> {
        let key_hash = self.hash_secret(raw_key);
        let row = sqlx::query_as::<_, ApiKeyRow>(
            r#"
            SELECT principal_id, permissions, created_at, expires_at, revoked_at
            FROM api_keys
            WHERE key_hash = $1
            "#,
        )
        .bind(key_hash)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|value| StoredApiKey {
            owner_id: value.principal_id,
            permissions: Self::permissions_from_json(value.permissions),
            created_at: value.created_at,
            expires_at: value.expires_at,
            revoked: value.revoked_at.is_some(),
        }))
    }

    pub async fn revoke_api_key(&self, raw_key: &str) -> Result<bool, sqlx::Error> {
        let key_hash = self.hash_secret(raw_key);
        let result = sqlx::query(
            r#"
            UPDATE api_keys
            SET revoked_at = NOW()
            WHERE key_hash = $1 AND revoked_at IS NULL
            "#,
        )
        .bind(key_hash)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn list_api_keys(&self) -> Result<Vec<(String, StoredApiKey)>, sqlx::Error> {
        let rows = sqlx::query_as::<_, ApiKeyListRow>(
            r#"
            SELECT key_hash, principal_id, permissions, created_at, expires_at, revoked_at
            FROM api_keys
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| {
                (
                    row.key_hash,
                    StoredApiKey {
                        owner_id: row.principal_id,
                        permissions: Self::permissions_from_json(row.permissions),
                        created_at: row.created_at,
                        expires_at: row.expires_at,
                        revoked: row.revoked_at.is_some(),
                    },
                )
            })
            .collect())
    }

    pub async fn insert_refresh_token(
        &self,
        refresh_token: &str,
        principal_id: &str,
        family_id: &str,
        parent_refresh_token: Option<&str>,
        expires_at: DateTime<Utc>,
    ) -> Result<(), sqlx::Error> {
        let token_hash = self.hash_secret(refresh_token);
        let parent_hash = parent_refresh_token.map(|token| self.hash_secret(token));

        sqlx::query(
            r#"
            INSERT INTO refresh_tokens (token_hash, principal_id, family_id, parent_token_hash, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(token_hash)
        .bind(principal_id)
        .bind(family_id)
        .bind(parent_hash)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn find_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<StoredRefreshToken>, sqlx::Error> {
        let token_hash = self.hash_secret(refresh_token);
        let row = sqlx::query_as::<_, RefreshTokenRow>(
            r#"
            SELECT family_id, replaced_by_token_hash, expires_at, revoked_at
            FROM refresh_tokens
            WHERE token_hash = $1
            "#,
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|value| StoredRefreshToken {
            family_id: value.family_id,
            replaced_by_token_hash: value.replaced_by_token_hash,
            expires_at: value.expires_at,
            revoked_at: value.revoked_at,
        }))
    }

    /// Atomically claim `old_refresh_token` and persist its replacement in a single
    /// transaction. Returns `Ok(false)` when the old token was already rotated or
    /// revoked (a concurrent or replayed refresh), in which case nothing is written.
    /// The conditional `UPDATE` is the serialization point: of two concurrent
    /// refreshes of the same token, exactly one flips `replaced_by_token_hash` from
    /// NULL and proceeds; the other matches zero rows and is rejected as replay.
    pub async fn rotate_refresh_token(
        &self,
        old_refresh_token: &str,
        new_refresh_token: &str,
        principal_id: &str,
        family_id: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, sqlx::Error> {
        let old_hash = self.hash_secret(old_refresh_token);
        let new_hash = self.hash_secret(new_refresh_token);

        let mut tx = self.pool.begin().await?;

        let claimed = sqlx::query(
            r#"
            UPDATE refresh_tokens
            SET replaced_by_token_hash = $2
            WHERE token_hash = $1
              AND replaced_by_token_hash IS NULL
              AND revoked_at IS NULL
            "#,
        )
        .bind(&old_hash)
        .bind(&new_hash)
        .execute(&mut *tx)
        .await?;

        if claimed.rows_affected() == 0 {
            tx.rollback().await?;
            return Ok(false);
        }

        sqlx::query(
            r#"
            INSERT INTO refresh_tokens (token_hash, principal_id, family_id, parent_token_hash, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(&new_hash)
        .bind(principal_id)
        .bind(family_id)
        .bind(&old_hash)
        .bind(expires_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(true)
    }

    pub async fn revoke_refresh_token(&self, refresh_token: &str) -> Result<bool, sqlx::Error> {
        let token_hash = self.hash_secret(refresh_token);
        let result = sqlx::query(
            r#"
            UPDATE refresh_tokens
            SET revoked_at = NOW()
            WHERE token_hash = $1 AND revoked_at IS NULL
            "#,
        )
        .bind(token_hash)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn revoke_refresh_family(&self, family_id: &str) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE refresh_tokens
            SET revoked_at = NOW()
            WHERE family_id = $1 AND revoked_at IS NULL
            "#,
        )
        .bind(family_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }
}
