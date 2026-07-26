//! Authentication Manager
//! Handles API key/JWT validation and permission checking.

pub mod repo;
pub mod token;

use std::sync::Arc;

use anyhow::{anyhow, Context};

use crate::core::error::HyperTideError;
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use self::repo::AuthRepo;
use self::token::{TokenPair, TokenService};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Permission {
    Lock,
    Upload,
    Download,
    Admin,
}

impl Permission {
    pub fn as_str(&self) -> &'static str {
        match self {
            Permission::Lock => "lock",
            Permission::Upload => "upload",
            Permission::Download => "download",
            Permission::Admin => "admin",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "lock" => Some(Permission::Lock),
            "upload" => Some(Permission::Upload),
            "download" => Some(Permission::Download),
            "admin" => Some(Permission::Admin),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub key: String,
    pub owner_id: String,
    pub permissions: Vec<Permission>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked: bool,
}

impl ApiKey {
    pub fn is_valid(&self) -> bool {
        if self.revoked {
            return false;
        }
        if let Some(expires) = self.expires_at {
            return Utc::now() < expires;
        }
        true
    }

    pub fn has_permission(&self, perm: Permission) -> bool {
        if self.permissions.contains(&Permission::Admin) {
            return true;
        }
        self.permissions.contains(&perm)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthSource {
    ApiKey,
    Bearer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthIdentity {
    pub owner_id: String,
    pub permissions: Vec<Permission>,
    pub source: AuthSource,
}

impl AuthIdentity {
    pub fn has_permission(&self, perm: Permission) -> bool {
        if self.permissions.contains(&Permission::Admin) {
            return true;
        }
        self.permissions.contains(&perm)
    }
}

const DEFAULT_KEY_CACHE_TTL_SECS: i64 = 60;

/// A cached API key together with the instant it was cached. Cache entries expire
/// after `key_cache_ttl_secs` so that a revocation or permission change made in the
/// database (possibly by another instance) is picked up within the TTL instead of
/// being trusted forever.
#[derive(Clone)]
struct CachedKey {
    api_key: ApiKey,
    cached_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct AuthManager {
    keys: Arc<DashMap<String, CachedKey>>,
    dev_master_key: Option<String>,
    repo: Option<AuthRepo>,
    token_service: Option<TokenService>,
    access_token_ttl_secs: i64,
    refresh_token_ttl_secs: i64,
    key_cache_ttl_secs: i64,
}

impl AuthManager {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(DashMap::new()),
            dev_master_key: None,
            repo: None,
            token_service: None,
            access_token_ttl_secs: 15 * 60,
            refresh_token_ttl_secs: 7 * 24 * 60 * 60,
            key_cache_ttl_secs: DEFAULT_KEY_CACHE_TTL_SECS,
        }
    }

    pub fn with_dev_key(master_key: impl Into<String>) -> Self {
        let master_key = master_key.into();
        let manager = Self {
            keys: Arc::new(DashMap::new()),
            dev_master_key: Some(master_key.clone()),
            repo: None,
            token_service: None,
            access_token_ttl_secs: 15 * 60,
            refresh_token_ttl_secs: 7 * 24 * 60 * 60,
            key_cache_ttl_secs: DEFAULT_KEY_CACHE_TTL_SECS,
        };

        let dev_api_key = ApiKey {
            key: master_key,
            owner_id: "dev-admin".to_string(),
            permissions: vec![
                Permission::Lock,
                Permission::Upload,
                Permission::Download,
                Permission::Admin,
            ],
            created_at: Utc::now(),
            expires_at: None,
            revoked: false,
        };
        manager.cache_key(dev_api_key);

        manager
    }

    pub async fn with_dev_key_and_db(
        master_key: impl Into<String>,
        db_pool: PgPool,
    ) -> anyhow::Result<Self> {
        let mut manager = Self::with_dev_key(master_key);
        let pepper = std::env::var("AUTH_PEPPER").unwrap_or_else(|_| "hypertide-dev-pepper".into());
        let repo = AuthRepo::new(db_pool, pepper);
        let token_service = TokenService::from_env()
            .map_err(|error| anyhow!("JWT service initialization failed: {error}"))?;
        manager.access_token_ttl_secs = std::env::var("ACCESS_TOKEN_TTL_SECS")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(15 * 60);
        manager.refresh_token_ttl_secs = std::env::var("REFRESH_TOKEN_TTL_SECS")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(7 * 24 * 60 * 60);
        manager.key_cache_ttl_secs = std::env::var("API_KEY_CACHE_TTL_SECS")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .filter(|secs| *secs >= 0)
            .unwrap_or(DEFAULT_KEY_CACHE_TTL_SECS);

        if let Some(master) = manager.dev_master_key.clone() {
            repo.upsert_api_key(
                &master,
                "dev-admin",
                &[
                    Permission::Lock,
                    Permission::Upload,
                    Permission::Download,
                    Permission::Admin,
                ],
                None,
            )
            .await
            .context("failed to persist dev master key")?;
        }

        manager.repo = Some(repo);
        manager.token_service = Some(token_service);
        Ok(manager)
    }

    fn cache_key(&self, api_key: ApiKey) {
        self.keys.insert(
            api_key.key.clone(),
            CachedKey {
                api_key,
                cached_at: Utc::now(),
            },
        );
    }

    fn cache_entry_fresh(&self, cached_at: DateTime<Utc>) -> bool {
        Utc::now() < cached_at + Duration::seconds(self.key_cache_ttl_secs.max(0))
    }

    pub fn validate_key(&self, key: &str) -> Option<ApiKey> {
        self.keys.get(key).and_then(|entry| {
            // A stale entry is treated as a miss so callers with a DB fall through
            // (validate_key_any) re-check the authoritative record.
            if self.cache_entry_fresh(entry.cached_at) && entry.api_key.is_valid() {
                Some(entry.api_key.clone())
            } else {
                None
            }
        })
    }

    pub fn has_permission(&self, key: &str, perm: Permission) -> bool {
        self.validate_key(key)
            .map(|api_key| api_key.has_permission(perm))
            .unwrap_or(false)
    }

    pub fn generate_key(
        &self,
        owner_id: &str,
        permissions: Vec<Permission>,
        expires_in_days: Option<i64>,
    ) -> ApiKey {
        let key = format!("ht_{}", Uuid::new_v4().to_string().replace('-', ""));
        let expires_at = expires_in_days.map(|days| Utc::now() + chrono::Duration::days(days));

        let api_key = ApiKey {
            key: key.clone(),
            owner_id: owner_id.to_string(),
            permissions,
            created_at: Utc::now(),
            expires_at,
            revoked: false,
        };

        self.cache_key(api_key.clone());
        api_key
    }

    pub fn revoke_key(&self, key: &str) -> bool {
        if let Some(mut entry) = self.keys.get_mut(key) {
            entry.api_key.revoked = true;
            true
        } else {
            false
        }
    }

    pub fn list_keys(&self) -> Vec<ApiKey> {
        self.keys
            .iter()
            .map(|kv| kv.value().api_key.clone())
            .collect()
    }

    pub async fn validate_key_any(&self, key: &str) -> Option<ApiKey> {
        if let Some(in_memory) = self.validate_key(key) {
            return Some(in_memory);
        }

        let repo = self.repo.as_ref()?;
        let stored = match repo.find_api_key(key).await {
            Ok(value) => value,
            Err(error) => {
                tracing::error!("api key lookup failed: {error}");
                return None;
            }
        }?;

        let api_key = ApiKey {
            key: key.to_string(),
            owner_id: stored.owner_id,
            permissions: stored.permissions,
            created_at: stored.created_at,
            expires_at: stored.expires_at,
            revoked: stored.revoked,
        };
        if api_key.is_valid() {
            self.cache_key(api_key.clone());
            Some(api_key)
        } else {
            // Drop any stale cached copy so a key revoked in the DB stops
            // authenticating from cache on this instance too.
            self.keys.remove(key);
            None
        }
    }

    pub async fn validate_api_key_identity(
        &self,
        key: &str,
    ) -> Result<AuthIdentity, HyperTideError> {
        let api_key = self
            .validate_key_any(key)
            .await
            .ok_or_else(|| HyperTideError::Authentication("Invalid API key".to_string()))?;
        Ok(AuthIdentity {
            owner_id: api_key.owner_id,
            permissions: api_key.permissions,
            source: AuthSource::ApiKey,
        })
    }

    pub async fn validate_access_token(&self, token: &str) -> Result<AuthIdentity, HyperTideError> {
        let token_service = self.token_service.as_ref().ok_or_else(|| {
            HyperTideError::Configuration("JWT service not configured".to_string())
        })?;
        let claims = token_service
            .decode_access_token(token)
            .map_err(HyperTideError::Authentication)?;
        let permissions = claims
            .permissions
            .iter()
            .filter_map(|value| Permission::from_str(value))
            .collect::<Vec<_>>();

        Ok(AuthIdentity {
            owner_id: claims.sub,
            permissions,
            source: AuthSource::Bearer,
        })
    }

    pub async fn generate_key_persistent(
        &self,
        owner_id: &str,
        permissions: Vec<Permission>,
        expires_in_days: Option<i64>,
    ) -> Result<ApiKey, HyperTideError> {
        let api_key = self.generate_key(owner_id, permissions.clone(), expires_in_days);
        if let Some(repo) = &self.repo {
            repo.upsert_api_key(&api_key.key, owner_id, &permissions, api_key.expires_at)
                .await
                .map_err(|error| {
                    HyperTideError::Persistence(format!("failed to persist api key: {error}"))
                })?;
        }
        Ok(api_key)
    }

    pub async fn revoke_key_persistent(&self, key: &str) -> Result<bool, HyperTideError> {
        let in_memory_revoked = self.revoke_key(key);
        let db_revoked = if let Some(repo) = &self.repo {
            repo.revoke_api_key(key).await.map_err(|error| {
                HyperTideError::Persistence(format!("failed to revoke api key: {error}"))
            })?
        } else {
            false
        };
        Ok(in_memory_revoked || db_revoked)
    }

    pub async fn list_keys_persistent(&self) -> Result<Vec<ApiKey>, HyperTideError> {
        // When a DB is configured it is the authoritative store and holds only
        // hashed keys. Return those exclusively: merging the in-memory cache here
        // duplicated persisted keys and, worse, exposed the raw secret bytes of
        // cached keys (dev master / freshly generated) to `list_keys`.
        if let Some(repo) = &self.repo {
            let stored = repo.list_api_keys().await.map_err(|error| {
                HyperTideError::Persistence(format!("failed to list api keys: {error}"))
            })?;
            return Ok(stored
                .into_iter()
                .map(|(key_hash, row)| ApiKey {
                    key: key_hash,
                    owner_id: row.owner_id,
                    permissions: row.permissions,
                    created_at: row.created_at,
                    expires_at: row.expires_at,
                    revoked: row.revoked,
                })
                .collect());
        }
        Ok(self.list_keys())
    }

    pub async fn exchange_key_for_tokens(
        &self,
        api_key: &str,
    ) -> Result<TokenPair, HyperTideError> {
        let key = self
            .validate_key_any(api_key)
            .await
            .ok_or_else(|| HyperTideError::Authentication("Invalid API key".to_string()))?;
        let token_service = self.token_service.as_ref().ok_or_else(|| {
            HyperTideError::Configuration("JWT service not configured".to_string())
        })?;
        let repo = self.repo.as_ref().ok_or_else(|| {
            HyperTideError::Configuration("Auth repository not configured".to_string())
        })?;

        let permissions = key
            .permissions
            .iter()
            .map(|permission| permission.as_str().to_string())
            .collect::<Vec<_>>();
        let family_id = Uuid::new_v4().to_string();

        let access_token = token_service
            .issue_access_token(
                &key.owner_id,
                permissions.clone(),
                self.access_token_ttl_secs,
            )
            .map_err(HyperTideError::Authentication)?;
        let refresh_token = token_service
            .issue_refresh_token(
                &key.owner_id,
                permissions,
                self.refresh_token_ttl_secs,
                family_id.clone(),
                None,
            )
            .map_err(HyperTideError::Authentication)?;

        repo.insert_refresh_token(
            &refresh_token,
            &key.owner_id,
            &family_id,
            None,
            Utc::now() + Duration::seconds(self.refresh_token_ttl_secs),
        )
        .await
        .map_err(|error| {
            HyperTideError::Persistence(format!("failed to persist refresh token: {error}"))
        })?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.access_token_ttl_secs,
        })
    }

    pub async fn refresh_tokens(&self, refresh_token: &str) -> Result<TokenPair, HyperTideError> {
        let token_service = self.token_service.as_ref().ok_or_else(|| {
            HyperTideError::Configuration("JWT service not configured".to_string())
        })?;
        let repo = self.repo.as_ref().ok_or_else(|| {
            HyperTideError::Configuration("Auth repository not configured".to_string())
        })?;

        let claims = token_service
            .decode_refresh_token(refresh_token)
            .map_err(HyperTideError::Authentication)?;
        let stored = repo
            .find_refresh_token(refresh_token)
            .await
            .map_err(|error| {
                HyperTideError::Persistence(format!("refresh lookup failed: {error}"))
            })?
            .ok_or_else(|| HyperTideError::Authentication("Refresh token not found".to_string()))?;

        if stored.revoked_at.is_some() {
            return Err(HyperTideError::Authentication(
                "Refresh token revoked".to_string(),
            ));
        }
        if stored.replaced_by_token_hash.is_some() {
            let _ = repo.revoke_refresh_family(&stored.family_id).await;
            return Err(HyperTideError::Authentication(
                "Refresh token replay detected; family revoked".to_string(),
            ));
        }
        if stored.expires_at <= Utc::now() {
            let _ = repo.revoke_refresh_token(refresh_token).await;
            return Err(HyperTideError::Authentication(
                "Refresh token expired".to_string(),
            ));
        }

        let family_id = claims
            .family_id
            .clone()
            .unwrap_or_else(|| stored.family_id.clone());
        let access_token = token_service
            .issue_access_token(
                &claims.sub,
                claims.permissions.clone(),
                self.access_token_ttl_secs,
            )
            .map_err(HyperTideError::Authentication)?;
        let new_refresh_token = token_service
            .issue_refresh_token(
                &claims.sub,
                claims.permissions,
                self.refresh_token_ttl_secs,
                family_id.clone(),
                Some(claims.jti),
            )
            .map_err(HyperTideError::Authentication)?;

        let rotated = repo
            .rotate_refresh_token(
                refresh_token,
                &new_refresh_token,
                &claims.sub,
                &family_id,
                Utc::now() + Duration::seconds(self.refresh_token_ttl_secs),
            )
            .await
            .map_err(|error| {
                HyperTideError::Persistence(format!("failed to rotate refresh token: {error}"))
            })?;
        if !rotated {
            // The token was claimed by a concurrent refresh or revoked between our
            // read above and this atomic claim: treat as replay and burn the family.
            let _ = repo.revoke_refresh_family(&stored.family_id).await;
            return Err(HyperTideError::Authentication(
                "Refresh token replay detected; family revoked".to_string(),
            ));
        }

        Ok(TokenPair {
            access_token,
            refresh_token: new_refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.access_token_ttl_secs,
        })
    }

    pub async fn revoke_refresh_token(&self, refresh_token: &str) -> Result<bool, HyperTideError> {
        let repo = self.repo.as_ref().ok_or_else(|| {
            HyperTideError::Configuration("Auth repository not configured".to_string())
        })?;
        repo.revoke_refresh_token(refresh_token)
            .await
            .map_err(|error| {
                HyperTideError::Persistence(format!("failed to revoke refresh token: {error}"))
            })
    }

    pub fn is_dev_master_key(&self, key: &str) -> bool {
        self.dev_master_key
            .as_ref()
            .map(|k| k == key)
            .unwrap_or(false)
    }
}

impl Default for AuthManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dev_master_key() {
        let manager = AuthManager::with_dev_key("test-master-key");

        assert!(manager.validate_key("test-master-key").is_some());
        assert!(manager.has_permission("test-master-key", Permission::Admin));
        assert!(manager.has_permission("test-master-key", Permission::Lock));
        assert!(manager.has_permission("test-master-key", Permission::Upload));
    }

    #[test]
    fn test_generate_and_validate_key() {
        let manager = AuthManager::new();

        let api_key =
            manager.generate_key("alice", vec![Permission::Lock, Permission::Download], None);

        assert!(manager.validate_key(&api_key.key).is_some());
        assert!(manager.has_permission(&api_key.key, Permission::Lock));
        assert!(manager.has_permission(&api_key.key, Permission::Download));
        assert!(!manager.has_permission(&api_key.key, Permission::Admin));
    }

    #[test]
    fn test_revoke_key() {
        let manager = AuthManager::new();

        let api_key = manager.generate_key("bob", vec![Permission::Upload], None);
        assert!(manager.validate_key(&api_key.key).is_some());

        assert!(manager.revoke_key(&api_key.key));
        assert!(manager.validate_key(&api_key.key).is_none());
    }

    #[test]
    fn test_invalid_key() {
        let manager = AuthManager::new();

        assert!(manager.validate_key("invalid-key").is_none());
        assert!(!manager.has_permission("invalid-key", Permission::Lock));
    }
}
