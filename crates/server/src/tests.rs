use crate::core::auth::AuthManager;
use crate::core::compliance::RetentionPolicy;
use crate::core::config::{AppConfig, AppEnv, LogFormat};
use crate::core::lock::LockManager;
use crate::core::session::SessionManager;
use crate::core::storage::StorageManager;
use crate::core::versioning::VersionManager;
use crate::core::witness::WitnessService;
use crate::routes::{build_app, DEFAULT_BODY_LIMIT_BYTES};
use crate::state::{AppState, HttpMetrics, RateLimiter};
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{HeaderValue, Request, StatusCode},
};
use serde_json::Value;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{net::SocketAddr, path::PathBuf};
use tower::util::ServiceExt;

fn test_master_key() -> &'static str {
    "dev-master-key"
}

fn test_config() -> AppConfig {
    AppConfig {
        app_env: AppEnv::Development,
        master_key: test_master_key().to_string(),
        storage_path: "./storage".to_string(),
        cors_allowed_origins: Vec::<HeaderValue>::new(),
        rate_limit_requests_per_minute: 600,
        trusted_proxy_cidrs: Vec::new(),
        log_format: LogFormat::Plain,
    }
}

fn test_config_with_rate_limit(limit: u64) -> AppConfig {
    AppConfig {
        rate_limit_requests_per_minute: limit,
        ..test_config()
    }
}

fn test_state() -> AppState {
    AppState {
        lock_manager: LockManager::new(),
        storage_manager: StorageManager::new("./storage"),
        auth_manager: AuthManager::with_dev_key(test_master_key()),
        version_manager: VersionManager::new(),
        session_manager: SessionManager::new(),
        event_store: None,
        audit_chain: None,
        checkpoint_service: None,
        witness_service: None,
        high_risk_guard: None,
        replay_service: None,
        retention_policy: RetentionPolicy::from_env(),
        db_pool: None,
        metrics: HttpMetrics::default(),
        rate_limiter: RateLimiter::new(600),
    }
}

async fn test_state_with_temp_storage() -> AppState {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let storage_root: PathBuf = std::env::temp_dir()
        .join("hypertide-server-tests")
        .join(unique.to_string());
    let storage_manager = StorageManager::new(&storage_root);
    storage_manager.init().await.expect("storage init");
    AppState {
        storage_manager,
        ..test_state()
    }
}

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct TestEnvGuard {
    _lock: MutexGuard<'static, ()>,
    saved: Vec<(String, Option<String>)>,
}

impl TestEnvGuard {
    fn set(vars: &[(&str, &str)]) -> Self {
        let lock = env_lock().lock().expect("env lock");
        let mut saved = Vec::with_capacity(vars.len());
        for (key, value) in vars {
            saved.push(((*key).to_string(), std::env::var(key).ok()));
            unsafe { std::env::set_var(key, value) };
        }
        Self { _lock: lock, saved }
    }
}

impl Drop for TestEnvGuard {
    fn drop(&mut self) {
        for (key, value) in self.saved.iter().rev() {
            match value {
                Some(value) => unsafe { std::env::set_var(key, value) },
                None => unsafe { std::env::remove_var(key) },
            }
        }
    }
}

fn test_pg_pool() -> PgPool {
    PgPoolOptions::new()
        .connect_lazy("postgres://hypertide:hypertide@localhost/hypertide")
        .expect("lazy pool")
}

#[tokio::test]
async fn exists_route_rejects_invalid_hashes() {
    let app = build_app(test_state(), &test_config());

    let request = Request::builder()
        .uri("/v2/storage/exists/abcdef")
        .header("X-API-Key", test_master_key())
        .body(Body::empty())
        .expect("request");

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let payload: Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(payload["success"], Value::Bool(false));
}

#[tokio::test]
async fn exists_route_returns_false_for_valid_missing_hash() {
    let app = build_app(test_state(), &test_config());
    let hash = "0".repeat(64);
    let request = Request::builder()
        .uri(format!("/v2/storage/exists/{hash}"))
        .header("X-API-Key", test_master_key())
        .body(Body::empty())
        .expect("request");

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let payload: Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(payload["data"], Value::Bool(false));
}

#[tokio::test]
async fn lock_route_rejects_missing_api_key() {
    let app = build_app(test_state(), &test_config());

    let request = Request::builder()
        .method("POST")
        .uri("/v2/locks/acquire")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"file_path":"assets/a.txt","owner_id":"alice"}"#,
        ))
        .expect("request");

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn lock_route_rejects_spoofed_owner_id() {
    let app = build_app(test_state(), &test_config());

    let request = Request::builder()
        .method("POST")
        .uri("/v2/locks/acquire")
        .header("content-type", "application/json")
        .header("X-API-Key", test_master_key())
        .body(Body::from(
            r#"{"file_path":"assets/a.txt","owner_id":"spoofed-user"}"#,
        ))
        .expect("request");

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn lock_route_uses_authenticated_owner_when_owner_not_provided() {
    let app = build_app(test_state(), &test_config());

    let request = Request::builder()
        .method("POST")
        .uri("/v2/locks/acquire")
        .header("content-type", "application/json")
        .header("X-API-Key", test_master_key())
        .body(Body::from(
            r#"{"file_path":"assets/no-owner.txt","repo_id":"repo-a"}"#,
        ))
        .expect("request");

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let payload: Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(
        payload["data"]["owner_id"],
        Value::String("dev-admin".to_string())
    );
}

#[tokio::test]
async fn non_upload_routes_reject_oversized_request_body() {
    let app = build_app(test_state(), &test_config());
    let oversized_data = "A".repeat(DEFAULT_BODY_LIMIT_BYTES + 1024);
    let payload = format!(r#"{{"data":"{oversized_data}"}}"#);

    let request = Request::builder()
        .method("POST")
        .uri("/v2/storage/hash")
        .header("content-type", "application/json")
        .header("X-API-Key", test_master_key())
        .body(Body::from(payload))
        .expect("request");

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn upload_routes_allow_request_body_larger_than_default_limit() {
    let app = build_app(test_state(), &test_config());
    let body = vec![b'x'; DEFAULT_BODY_LIMIT_BYTES + 1024];

    let request = Request::builder()
        .method("PUT")
        .uri("/v2/blobs/chunks/not-a-valid-hash")
        .header("X-API-Key", test_master_key())
        .body(Body::from(body))
        .expect("request");

    let response = app.oneshot(request).await.expect("response");
    assert_ne!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn compose_blob_reassembles_uploaded_chunks() {
    let app = build_app(test_state_with_temp_storage().await, &test_config());
    let chunk_one = b"hello ".to_vec();
    let chunk_two = b"world".to_vec();
    let chunk_one_hash = StorageManager::calculate_hash(&chunk_one);
    let chunk_two_hash = StorageManager::calculate_hash(&chunk_two);

    for (hash, body) in [
        (&chunk_one_hash, chunk_one.clone()),
        (&chunk_two_hash, chunk_two.clone()),
    ] {
        let request = Request::builder()
            .method("PUT")
            .uri(format!("/v2/blobs/chunks/{hash}"))
            .header("X-API-Key", test_master_key())
            .body(Body::from(body))
            .expect("request");

        let response = app.clone().oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    }

    let manifest_payload = serde_json::json!({
        "version": 1,
        "chunk_size_policy": "fixed-4m",
        "chunks": [
            { "i": 0, "chunk_hash": chunk_one_hash, "size": 6 },
            { "i": 1, "chunk_hash": chunk_two_hash, "size": 5 }
        ],
        "file_meta": { "name": "hello.txt" }
    });
    let manifest_request = Request::builder()
        .method("POST")
        .uri("/v2/manifests")
        .header("X-API-Key", test_master_key())
        .header("content-type", "application/json")
        .body(Body::from(manifest_payload.to_string()))
        .expect("request");

    let manifest_response = app
        .clone()
        .oneshot(manifest_request)
        .await
        .expect("response");
    assert_eq!(manifest_response.status(), StatusCode::CREATED);
    let manifest_body = to_bytes(manifest_response.into_body(), usize::MAX)
        .await
        .expect("body");
    let manifest_json: Value = serde_json::from_slice(&manifest_body).expect("json");
    let manifest_hash = manifest_json["data"]["manifest_hash"]
        .as_str()
        .expect("manifest hash")
        .to_string();

    let compose_payload = serde_json::json!({ "manifest_hash": manifest_hash });
    let compose_request = Request::builder()
        .method("POST")
        .uri("/v2/blobs/compose")
        .header("X-API-Key", test_master_key())
        .header("content-type", "application/json")
        .body(Body::from(compose_payload.to_string()))
        .expect("request");

    let compose_response = app
        .clone()
        .oneshot(compose_request)
        .await
        .expect("response");
    assert_eq!(compose_response.status(), StatusCode::OK);
    let compose_body = to_bytes(compose_response.into_body(), usize::MAX)
        .await
        .expect("body");
    let compose_json: Value = serde_json::from_slice(&compose_body).expect("json");
    let blob_hash = compose_json["data"]["blob_hash"]
        .as_str()
        .expect("blob hash");
    assert_eq!(
        blob_hash,
        StorageManager::calculate_hash(b"hello world"),
        "compose should produce the canonical blob hash"
    );

    let download_request = Request::builder()
        .uri(format!("/v2/storage/download/{blob_hash}"))
        .header("X-API-Key", test_master_key())
        .body(Body::empty())
        .expect("request");
    let download_response = app
        .oneshot(download_request)
        .await
        .expect("download response");
    assert_eq!(download_response.status(), StatusCode::OK);
    let download_body = to_bytes(download_response.into_body(), usize::MAX)
        .await
        .expect("download body");
    assert_eq!(download_body.as_ref(), b"hello world");
}

#[tokio::test]
async fn ready_returns_503_without_db_pool() {
    let app = build_app(test_state(), &test_config());

    let request = Request::builder()
        .uri("/health/ready")
        .body(Body::empty())
        .expect("request");

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn metrics_route_exposes_prometheus_counters() {
    let app = build_app(test_state(), &test_config());

    let health_request = Request::builder()
        .uri("/health/live")
        .body(Body::empty())
        .expect("health request");
    let health_response = app
        .clone()
        .oneshot(health_request)
        .await
        .expect("health response");
    assert_eq!(health_response.status(), StatusCode::OK);
    assert!(health_response.headers().contains_key("x-request-id"));

    let ready_request = Request::builder()
        .uri("/health/ready")
        .body(Body::empty())
        .expect("ready request");
    let ready_response = app
        .clone()
        .oneshot(ready_request)
        .await
        .expect("ready response");
    assert_eq!(ready_response.status(), StatusCode::SERVICE_UNAVAILABLE);

    let metrics_request = Request::builder()
        .uri("/metrics")
        .body(Body::empty())
        .expect("metrics request");
    let metrics_response = app
        .oneshot(metrics_request)
        .await
        .expect("metrics response");
    assert_eq!(metrics_response.status(), StatusCode::OK);

    let body = to_bytes(metrics_response.into_body(), usize::MAX)
        .await
        .expect("metrics body");
    let text = String::from_utf8(body.to_vec()).expect("utf8 metrics");
    assert!(text.contains("hypertide_http_requests_total 2"));
    assert!(text.contains("hypertide_http_responses_total{status_class=\"2xx\"} 1"));
    assert!(text.contains(
        "hypertide_http_requests_total{method=\"GET\",route=\"/health/live\",status=\"200\"} 1"
    ));
    assert!(text.contains(
            "hypertide_http_request_duration_seconds_bucket{method=\"GET\",route=\"/health/live\",le=\"+Inf\"} 1"
        ));
    assert!(text.contains(
        "hypertide_business_events_total{event=\"db_readiness_failure\",status=\"503\"} 1"
    ));
}

#[tokio::test]
async fn rate_limit_returns_429_when_window_is_exhausted() {
    let app = build_app(test_state(), &test_config_with_rate_limit(1));

    let first = Request::builder()
        .uri("/health/live")
        .body(Body::empty())
        .expect("first request");
    let first_response = app.clone().oneshot(first).await.expect("first response");
    assert_eq!(first_response.status(), StatusCode::OK);

    let second = Request::builder()
        .uri("/health/live")
        .body(Body::empty())
        .expect("second request");
    let second_response = app.oneshot(second).await.expect("second response");
    assert_eq!(second_response.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn invalid_credentials_share_the_anonymous_rate_limit_bucket() {
    let app = build_app(test_state(), &test_config_with_rate_limit(1));

    let mut first = Request::builder()
        .uri("/health/live")
        .header("X-API-Key", "key-a")
        .body(Body::empty())
        .expect("first request");
    first.extensions_mut().insert(ConnectInfo(
        "192.0.2.1:4000".parse::<SocketAddr>().expect("peer"),
    ));
    let first_response = app.clone().oneshot(first).await.expect("first response");
    assert_eq!(first_response.status(), StatusCode::OK);

    let mut second = Request::builder()
        .uri("/health/live")
        .header("X-API-Key", "key-b")
        .body(Body::empty())
        .expect("second request");
    second.extensions_mut().insert(ConnectInfo(
        "192.0.2.1:5000".parse::<SocketAddr>().expect("peer"),
    ));
    let second_response = app.clone().oneshot(second).await.expect("second response");
    assert_eq!(second_response.status(), StatusCode::TOO_MANY_REQUESTS);

    let mut other_peer = Request::builder()
        .uri("/health/live")
        .header("X-API-Key", "key-c")
        .body(Body::empty())
        .expect("other peer request");
    other_peer.extensions_mut().insert(ConnectInfo(
        "192.0.2.2:4000".parse::<SocketAddr>().expect("peer"),
    ));
    let other_peer_response = app
        .clone()
        .oneshot(other_peer)
        .await
        .expect("other peer response");
    assert_eq!(other_peer_response.status(), StatusCode::OK);

    let authenticated = Request::builder()
        .uri("/health/live")
        .header("X-API-Key", test_master_key())
        .body(Body::empty())
        .expect("authenticated request");
    let authenticated_response = app
        .oneshot(authenticated)
        .await
        .expect("authenticated response");
    assert_eq!(authenticated_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn invalid_bearer_tokens_use_the_anonymous_peer_ip_bucket() {
    let app = build_app(test_state(), &test_config_with_rate_limit(1));

    let mut first = Request::builder()
        .uri("/health/live")
        .header("Authorization", "Bearer invalid-a")
        .body(Body::empty())
        .expect("first request");
    first.extensions_mut().insert(ConnectInfo(
        "192.0.2.1:4000".parse::<SocketAddr>().expect("peer"),
    ));
    let first_response = app.clone().oneshot(first).await.expect("first response");
    assert_eq!(first_response.status(), StatusCode::OK);

    let mut same_peer = Request::builder()
        .uri("/health/live")
        .header("Authorization", "Bearer invalid-b")
        .body(Body::empty())
        .expect("same peer request");
    same_peer.extensions_mut().insert(ConnectInfo(
        "192.0.2.1:5000".parse::<SocketAddr>().expect("peer"),
    ));
    let same_peer_response = app
        .clone()
        .oneshot(same_peer)
        .await
        .expect("same peer response");
    assert_eq!(same_peer_response.status(), StatusCode::TOO_MANY_REQUESTS);

    let mut other_peer = Request::builder()
        .uri("/health/live")
        .header("Authorization", "Bearer invalid-c")
        .body(Body::empty())
        .expect("other peer request");
    other_peer.extensions_mut().insert(ConnectInfo(
        "192.0.2.2:4000".parse::<SocketAddr>().expect("peer"),
    ));
    let other_peer_response = app.oneshot(other_peer).await.expect("other peer response");
    assert_eq!(other_peer_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn trusted_proxy_forwarded_clients_use_separate_anonymous_buckets() {
    let mut config = test_config_with_rate_limit(1);
    config.trusted_proxy_cidrs = vec!["10.0.0.0/8".parse().expect("cidr")];
    let app = build_app(test_state(), &config);

    let mut first = Request::builder()
        .uri("/health/live")
        .header("X-Forwarded-For", "192.0.2.1, 10.0.0.4")
        .body(Body::empty())
        .expect("first request");
    first.extensions_mut().insert(ConnectInfo(
        "10.0.0.5:4000".parse::<SocketAddr>().expect("proxy"),
    ));
    let first_response = app.clone().oneshot(first).await.expect("first response");
    assert_eq!(first_response.status(), StatusCode::OK);

    let mut second = Request::builder()
        .uri("/health/live")
        .header("X-Real-IP", "192.0.2.2")
        .body(Body::empty())
        .expect("second request");
    second.extensions_mut().insert(ConnectInfo(
        "10.0.0.5:5000".parse::<SocketAddr>().expect("proxy"),
    ));
    let second_response = app.oneshot(second).await.expect("second response");
    assert_eq!(second_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn untrusted_peers_cannot_spoof_forwarded_rate_limit_addresses() {
    let app = build_app(test_state(), &test_config_with_rate_limit(1));

    let mut first = Request::builder()
        .uri("/health/live")
        .header("X-Forwarded-For", "192.0.2.1")
        .body(Body::empty())
        .expect("first request");
    first.extensions_mut().insert(ConnectInfo(
        "198.51.100.5:4000".parse::<SocketAddr>().expect("peer"),
    ));
    let first_response = app.clone().oneshot(first).await.expect("first response");
    assert_eq!(first_response.status(), StatusCode::OK);

    let mut second = Request::builder()
        .uri("/health/live")
        .header("X-Forwarded-For", "192.0.2.2")
        .body(Body::empty())
        .expect("second request");
    second.extensions_mut().insert(ConnectInfo(
        "198.51.100.5:5000".parse::<SocketAddr>().expect("peer"),
    ));
    let second_response = app.oneshot(second).await.expect("second response");
    assert_eq!(second_response.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn auth_lookup_pre_limit_rejects_before_credential_bucket_selection() {
    let app = build_app(test_state(), &test_config_with_rate_limit(1));

    let mut invalid = Request::builder()
        .uri("/health/live")
        .header("X-API-Key", "invalid")
        .body(Body::empty())
        .expect("invalid request");
    invalid.extensions_mut().insert(ConnectInfo(
        "192.0.2.1:4000".parse::<SocketAddr>().expect("peer"),
    ));
    let invalid_response = app
        .clone()
        .oneshot(invalid)
        .await
        .expect("invalid response");
    assert_eq!(invalid_response.status(), StatusCode::OK);

    let mut valid = Request::builder()
        .uri("/health/live")
        .header("X-API-Key", test_master_key())
        .body(Body::empty())
        .expect("valid request");
    valid.extensions_mut().insert(ConnectInfo(
        "192.0.2.1:5000".parse::<SocketAddr>().expect("peer"),
    ));
    let valid_response = app.oneshot(valid).await.expect("valid response");
    assert_eq!(valid_response.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn manifest_rejects_composed_blobs_over_the_memory_limit() {
    let app = build_app(test_state(), &test_config());
    let payload = serde_json::json!({
        "version": 1,
        "chunk_size_policy": "fixed",
        "chunks": [{
            "i": 0,
            "chunk_hash": "0".repeat(64),
            "size": 268_435_457u64
        }],
        "file_meta": null
    });
    let request = Request::builder()
        .method("POST")
        .uri("/v2/manifests")
        .header("content-type", "application/json")
        .header("X-API-Key", test_master_key())
        .body(Body::from(payload.to_string()))
        .expect("request");

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn lock_release_returns_the_released_scoped_lock() {
    let app = build_app(test_state(), &test_config());
    let payload = serde_json::json!({
        "file_path": "assets/scoped.txt",
        "repo_id": "repo-a",
        "scope": "asset"
    });
    let acquire = Request::builder()
        .method("POST")
        .uri("/v2/locks/acquire")
        .header("content-type", "application/json")
        .header("X-API-Key", test_master_key())
        .body(Body::from(payload.to_string()))
        .expect("acquire request");
    assert_eq!(
        app.clone()
            .oneshot(acquire)
            .await
            .expect("acquire")
            .status(),
        StatusCode::OK
    );

    let release = Request::builder()
        .method("POST")
        .uri("/v2/locks/release")
        .header("content-type", "application/json")
        .header("X-API-Key", test_master_key())
        .body(Body::from(payload.to_string()))
        .expect("release request");
    let response = app.oneshot(release).await.expect("release");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let json: Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["data"]["repo_id"], "repo-a");
    assert_eq!(json["data"]["file_path"], "assets/scoped.txt");
}

#[tokio::test]
async fn lock_list_is_scoped_to_the_requested_repo() {
    let app = build_app(test_state(), &test_config());
    for repo_id in ["repo-a", "repo-b"] {
        let payload = serde_json::json!({
            "file_path": "assets/shared.txt",
            "repo_id": repo_id,
            "scope": "asset"
        });
        let request = Request::builder()
            .method("POST")
            .uri("/v2/locks/acquire")
            .header("content-type", "application/json")
            .header("X-API-Key", test_master_key())
            .body(Body::from(payload.to_string()))
            .expect("acquire request");
        assert_eq!(
            app.clone()
                .oneshot(request)
                .await
                .expect("response")
                .status(),
            StatusCode::OK
        );
    }

    let request = Request::builder()
        .uri("/v2/locks?repo_id=repo-a&scope=asset")
        .header("X-API-Key", test_master_key())
        .body(Body::empty())
        .expect("list request");
    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let json: Value = serde_json::from_slice(&body).expect("json");
    let locks = json["data"].as_array().expect("locks array");
    assert_eq!(locks.len(), 1);
    assert_eq!(locks[0]["repo_id"], "repo-a");
}

#[tokio::test]
async fn legacy_lock_blocks_repo_scoped_changeset_submit() {
    let state = test_state();
    state
        .lock_manager
        .try_lock(
            "Content/Legacy.uasset".to_string(),
            "legacy-owner".to_string(),
        )
        .await
        .expect("legacy lock");
    let app = build_app(state, &test_config());
    let payload = serde_json::json!({
        "repo_id": "repo-a",
        "branch": "main",
        "base_changeset_id": "ROOT",
        "author": "dev-admin",
        "message": "must respect legacy lock",
        "assets": [{
            "path": "Content/Legacy.uasset",
            "blob_hash": "0".repeat(64)
        }]
    });
    let request = Request::builder()
        .method("POST")
        .uri("/v2/changesets")
        .header("content-type", "application/json")
        .header("X-API-Key", test_master_key())
        .body(Body::from(payload.to_string()))
        .expect("submit request");

    let response = app.oneshot(request).await.expect("submit response");
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn submit_rejects_asset_paths_that_escape_the_workspace() {
    let app = build_app(test_state(), &test_config());
    let payload = serde_json::json!({
        "repo_id": "repo-path-safety",
        "branch": "main",
        "base_changeset_id": "ROOT",
        "author": "dev-admin",
        "message": "invalid path",
        "assets": [{ "path": "../../outside.txt", "blob_hash": null }]
    });
    let request = Request::builder()
        .method("POST")
        .uri("/v2/changesets")
        .header("content-type", "application/json")
        .header("X-API-Key", test_master_key())
        .body(Body::from(payload.to_string()))
        .expect("request");

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn replay_verify_returns_503_when_service_unavailable() {
    let app = build_app(test_state(), &test_config());

    let request = Request::builder()
        .method("POST")
        .uri("/v2/trust/replay/verify")
        .header("X-API-Key", test_master_key())
        .body(Body::empty())
        .expect("request");

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn replay_verify_rejects_missing_api_key() {
    let app = build_app(test_state(), &test_config());

    let request = Request::builder()
        .method("POST")
        .uri("/v2/trust/replay/verify")
        .body(Body::empty())
        .expect("request");

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn replay_readiness_returns_503_when_service_unavailable() {
    let app = build_app(test_state(), &test_config());

    let request = Request::builder()
        .uri("/v2/trust/replay/readiness")
        .header("X-API-Key", test_master_key())
        .body(Body::empty())
        .expect("request");

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn replay_readiness_rejects_missing_api_key() {
    let app = build_app(test_state(), &test_config());

    let request = Request::builder()
        .uri("/v2/trust/replay/readiness")
        .body(Body::empty())
        .expect("request");

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn changeset_gate_rejects_missing_api_key() {
    let app = build_app(test_state(), &test_config());

    let request = Request::builder()
        .uri("/v2/changesets/test-id/gate?repo_id=repo-a")
        .body(Body::empty())
        .expect("request");

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn changeset_gate_returns_not_found_for_unknown_repo() {
    let app = build_app(test_state(), &test_config());

    let request = Request::builder()
        .uri("/v2/changesets/test-id/gate?repo_id=repo-a")
        .header("X-API-Key", test_master_key())
        .body(Body::empty())
        .expect("request");

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn repo_routes_create_list_and_return_info() {
    let app = build_app(test_state(), &test_config());

    let create_payload = serde_json::json!({
        "repo_id": "repo-route",
        "default_branch": "main"
    });
    let create_request = Request::builder()
        .method("POST")
        .uri("/v2/repos")
        .header("content-type", "application/json")
        .header("X-API-Key", test_master_key())
        .body(Body::from(create_payload.to_string()))
        .expect("create request");
    let create_response = app
        .clone()
        .oneshot(create_request)
        .await
        .expect("create response");
    assert_eq!(create_response.status(), StatusCode::CREATED);

    let info_request = Request::builder()
        .uri("/v2/repos/repo-route")
        .header("X-API-Key", test_master_key())
        .body(Body::empty())
        .expect("info request");
    let info_response = app
        .clone()
        .oneshot(info_request)
        .await
        .expect("info response");
    assert_eq!(info_response.status(), StatusCode::OK);
    let info_body = to_bytes(info_response.into_body(), usize::MAX)
        .await
        .expect("info body");
    let info_json: Value = serde_json::from_slice(&info_body).expect("info json");
    assert_eq!(info_json["data"]["repo_id"], "repo-route");
    assert_eq!(info_json["data"]["default_branch"], "main");
    assert_eq!(info_json["data"]["branches"][0]["name"], "main");

    let list_request = Request::builder()
        .uri("/v2/repos")
        .header("X-API-Key", test_master_key())
        .body(Body::empty())
        .expect("list request");
    let list_response = app.oneshot(list_request).await.expect("list response");
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_body = to_bytes(list_response.into_body(), usize::MAX)
        .await
        .expect("list body");
    let list_json: Value = serde_json::from_slice(&list_body).expect("list json");
    assert_eq!(list_json["data"]["repos"][0]["repo_id"], "repo-route");
}

#[tokio::test]
async fn repo_create_rejects_missing_api_key_and_empty_repo() {
    let app = build_app(test_state(), &test_config());

    let unauth_request = Request::builder()
        .method("POST")
        .uri("/v2/repos")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"repo_id":"repo-route"}"#))
        .expect("unauth request");
    let unauth_response = app
        .clone()
        .oneshot(unauth_request)
        .await
        .expect("unauth response");
    assert_eq!(unauth_response.status(), StatusCode::UNAUTHORIZED);

    let invalid_request = Request::builder()
        .method("POST")
        .uri("/v2/repos")
        .header("content-type", "application/json")
        .header("X-API-Key", test_master_key())
        .body(Body::from(r#"{"repo_id":" ","default_branch":"main"}"#))
        .expect("invalid request");
    let invalid_response = app
        .oneshot(invalid_request)
        .await
        .expect("invalid response");
    assert_eq!(invalid_response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn session_checkpoint_routes_create_and_return_snapshot() {
    let app = build_app(test_state(), &test_config());

    let session_payload = serde_json::json!({
        "repo_id": "repo-agent",
        "branch": "main",
        "base_changeset_id": "ROOT",
        "workspace_root": "E:/workspace/game",
        "intent_id": "intent-1",
        "task_id": "task-1",
        "agent_run_id": "run-1",
        "trigger_reason": "agent_save",
        "risk_level": "local",
        "semantic_summary": "saving agent progress"
    });
    let session_request = Request::builder()
        .method("POST")
        .uri("/v2/sessions")
        .header("content-type", "application/json")
        .header("X-API-Key", test_master_key())
        .body(Body::from(session_payload.to_string()))
        .expect("session request");

    let session_response = app
        .clone()
        .oneshot(session_request)
        .await
        .expect("session response");
    assert_eq!(session_response.status(), StatusCode::CREATED);
    let session_body = to_bytes(session_response.into_body(), usize::MAX)
        .await
        .expect("session body");
    let session_json: Value = serde_json::from_slice(&session_body).expect("session json");
    let session_id = session_json["data"]["session_id"]
        .as_str()
        .expect("session id")
        .to_string();
    assert_eq!(
        session_json["data"]["actor_id"],
        Value::String("dev-admin".to_string())
    );

    let checkpoint_payload = serde_json::json!({
        "trigger_reason": "manual_checkpoint",
        "semantic_summary": "inventory draft checkpoint",
        "assets": [
            {
                "asset_id": "asset-inventory",
                "path": "Assets/inventory.json",
                "blob_hash": "hash-inventory"
            }
        ]
    });
    let checkpoint_request = Request::builder()
        .method("POST")
        .uri(format!("/v2/sessions/{session_id}/checkpoints"))
        .header("content-type", "application/json")
        .header("X-API-Key", test_master_key())
        .body(Body::from(checkpoint_payload.to_string()))
        .expect("checkpoint request");

    let checkpoint_response = app
        .clone()
        .oneshot(checkpoint_request)
        .await
        .expect("checkpoint response");
    assert_eq!(checkpoint_response.status(), StatusCode::CREATED);
    let checkpoint_body = to_bytes(checkpoint_response.into_body(), usize::MAX)
        .await
        .expect("checkpoint body");
    let checkpoint_json: Value = serde_json::from_slice(&checkpoint_body).expect("checkpoint json");
    let checkpoint_id = checkpoint_json["data"]["checkpoint_id"]
        .as_str()
        .expect("checkpoint id")
        .to_string();
    assert_eq!(
        checkpoint_json["data"]["parent_checkpoint_id"],
        Value::Null,
        "first checkpoint has no parent checkpoint"
    );

    let snapshot_request = Request::builder()
        .uri(format!("/v2/checkpoints/{checkpoint_id}/snapshot"))
        .header("X-API-Key", test_master_key())
        .body(Body::empty())
        .expect("snapshot request");
    let snapshot_response = app
        .clone()
        .oneshot(snapshot_request)
        .await
        .expect("snapshot response");
    assert_eq!(snapshot_response.status(), StatusCode::OK);
    let snapshot_body = to_bytes(snapshot_response.into_body(), usize::MAX)
        .await
        .expect("snapshot body");
    let snapshot_json: Value = serde_json::from_slice(&snapshot_body).expect("snapshot json");
    assert_eq!(
        snapshot_json["data"]["assets"][0]["path"],
        Value::String("Assets/inventory.json".to_string())
    );

    let list_request = Request::builder()
        .uri(format!("/v2/sessions/{session_id}/checkpoints"))
        .header("X-API-Key", test_master_key())
        .body(Body::empty())
        .expect("list request");
    let list_response = app.oneshot(list_request).await.expect("list response");
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_body = to_bytes(list_response.into_body(), usize::MAX)
        .await
        .expect("list body");
    let list_json: Value = serde_json::from_slice(&list_body).expect("list json");
    assert_eq!(
        list_json["data"]["items"].as_array().expect("items").len(),
        1
    );
}

#[tokio::test]
async fn submit_from_expired_checkpoint_is_rejected() {
    let app = build_app(test_state(), &test_config());

    let session_payload = serde_json::json!({
        "repo_id": "repo-agent-expired",
        "branch": "main",
        "base_changeset_id": "ROOT",
        "workspace_root": "E:/workspace/game"
    });
    let session_request = Request::builder()
        .method("POST")
        .uri("/v2/sessions")
        .header("content-type", "application/json")
        .header("X-API-Key", test_master_key())
        .body(Body::from(session_payload.to_string()))
        .expect("session request");
    let session_response = app
        .clone()
        .oneshot(session_request)
        .await
        .expect("session response");
    assert_eq!(session_response.status(), StatusCode::CREATED);
    let session_body = to_bytes(session_response.into_body(), usize::MAX)
        .await
        .expect("session body");
    let session_json: Value = serde_json::from_slice(&session_body).expect("session json");
    let session_id = session_json["data"]["session_id"]
        .as_str()
        .expect("session id")
        .to_string();

    let checkpoint_payload = serde_json::json!({
        "expires_at": "2000-01-01T00:00:00Z",
        "assets": [
            {
                "asset_id": "asset-a",
                "path": "Assets/a.txt",
                "blob_hash": "hash-a"
            }
        ]
    });
    let checkpoint_request = Request::builder()
        .method("POST")
        .uri(format!("/v2/sessions/{session_id}/checkpoints"))
        .header("content-type", "application/json")
        .header("X-API-Key", test_master_key())
        .body(Body::from(checkpoint_payload.to_string()))
        .expect("checkpoint request");
    let checkpoint_response = app
        .clone()
        .oneshot(checkpoint_request)
        .await
        .expect("checkpoint response");
    assert_eq!(checkpoint_response.status(), StatusCode::CREATED);
    let checkpoint_body = to_bytes(checkpoint_response.into_body(), usize::MAX)
        .await
        .expect("checkpoint body");
    let checkpoint_json: Value = serde_json::from_slice(&checkpoint_body).expect("checkpoint json");
    let checkpoint_id = checkpoint_json["data"]["checkpoint_id"]
        .as_str()
        .expect("checkpoint id");

    let submit_payload = serde_json::json!({
        "repo_id": "repo-agent-expired",
        "branch": "main",
        "base_changeset_id": "ROOT",
        "author": "dev-admin",
        "message": "submit from expired checkpoint",
        "parent_checkpoint_id": checkpoint_id,
        "assets": []
    });
    let submit_request = Request::builder()
        .method("POST")
        .uri("/v2/changesets")
        .header("content-type", "application/json")
        .header("X-API-Key", test_master_key())
        .body(Body::from(submit_payload.to_string()))
        .expect("submit request");
    let submit_response = app.oneshot(submit_request).await.expect("submit response");

    assert_eq!(submit_response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn submit_from_checkpoint_rejects_repo_or_branch_mismatch() {
    let app = build_app(test_state(), &test_config());

    let session_payload = serde_json::json!({
        "repo_id": "repo-source",
        "branch": "main",
        "base_changeset_id": "ROOT",
        "workspace_root": "E:/workspace/game"
    });
    let session_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v2/sessions")
                .header("content-type", "application/json")
                .header("X-API-Key", test_master_key())
                .body(Body::from(session_payload.to_string()))
                .expect("session request"),
        )
        .await
        .expect("session response");
    assert_eq!(session_response.status(), StatusCode::CREATED);
    let session_body = to_bytes(session_response.into_body(), usize::MAX)
        .await
        .expect("session body");
    let session_json: Value = serde_json::from_slice(&session_body).expect("session json");
    let session_id = session_json["data"]["session_id"]
        .as_str()
        .expect("session id")
        .to_string();

    let checkpoint_payload = serde_json::json!({
        "assets": []
    });
    let checkpoint_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v2/sessions/{session_id}/checkpoints"))
                .header("content-type", "application/json")
                .header("X-API-Key", test_master_key())
                .body(Body::from(checkpoint_payload.to_string()))
                .expect("checkpoint request"),
        )
        .await
        .expect("checkpoint response");
    assert_eq!(checkpoint_response.status(), StatusCode::CREATED);
    let checkpoint_body = to_bytes(checkpoint_response.into_body(), usize::MAX)
        .await
        .expect("checkpoint body");
    let checkpoint_json: Value = serde_json::from_slice(&checkpoint_body).expect("checkpoint json");
    let checkpoint_id = checkpoint_json["data"]["checkpoint_id"]
        .as_str()
        .expect("checkpoint id");

    let submit_payload = serde_json::json!({
        "repo_id": "repo-other",
        "branch": "main",
        "base_changeset_id": "ROOT",
        "author": "dev-admin",
        "message": "wrong repo",
        "parent_checkpoint_id": checkpoint_id,
        "assets": []
    });
    let submit_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v2/changesets")
                .header("content-type", "application/json")
                .header("X-API-Key", test_master_key())
                .body(Body::from(submit_payload.to_string()))
                .expect("submit request"),
        )
        .await
        .expect("submit response");

    assert_eq!(submit_response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn audit_export_rejects_missing_api_key() {
    let app = build_app(test_state(), &test_config());

    let request = Request::builder()
        .uri("/v2/trust/audit/export")
        .body(Body::empty())
        .expect("request");

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn audit_export_returns_503_when_service_unavailable() {
    let app = build_app(test_state(), &test_config());

    let request = Request::builder()
        .uri("/v2/trust/audit/export")
        .header("X-API-Key", test_master_key())
        .body(Body::empty())
        .expect("request");

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn retention_policy_rejects_missing_api_key() {
    let app = build_app(test_state(), &test_config());

    let request = Request::builder()
        .uri("/v2/trust/retention/policy")
        .body(Body::empty())
        .expect("request");

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn retention_policy_returns_ok_with_admin_key() {
    let app = build_app(test_state(), &test_config());

    let request = Request::builder()
        .uri("/v2/trust/retention/policy")
        .header("X-API-Key", test_master_key())
        .body(Body::empty())
        .expect("request");

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn witness_topology_rejects_missing_api_key() {
    let app = build_app(test_state(), &test_config());

    let request = Request::builder()
        .uri("/v2/trust/witness/topology")
        .body(Body::empty())
        .expect("request");

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn witness_topology_returns_503_when_service_unavailable() {
    let app = build_app(test_state(), &test_config());

    let request = Request::builder()
        .uri("/v2/trust/witness/topology")
        .header("X-API-Key", test_master_key())
        .body(Body::empty())
        .expect("request");

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn witness_topology_reports_cross_environment_groups() {
    let _env = TestEnvGuard::set(&[
        (
            "WITNESS_KEYS",
            "w1:s1:primary:studio-a,w2:s2:primary:studio-b,w3:s3:backup:studio-b",
        ),
        ("WITNESS_SCOPE", "cross-env"),
        ("WITNESS_QUORUM", "2"),
    ]);
    let mut state = test_state();
    state.witness_service = Some(WitnessService::from_env(test_pg_pool()));
    let app = build_app(state, &test_config());

    let request = Request::builder()
        .uri("/v2/trust/witness/topology")
        .header("X-API-Key", test_master_key())
        .body(Body::empty())
        .expect("request");

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let payload: Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(
        payload["data"]["scope"],
        Value::String("cross-env".to_string())
    );
    assert_eq!(
        payload["data"]["cross_environment"],
        Value::Bool(true),
        "topology should expose multi-environment layout"
    );
    assert_eq!(
        payload["data"]["cross_environment_quorum_possible"],
        Value::Bool(true),
        "topology should report whether quorum spans environments"
    );
    assert_eq!(
        payload["data"]["witness_scopes"][0]["environment"],
        Value::String("studio-a".to_string())
    );
    assert_eq!(
        payload["data"]["environments"][0]["environment"],
        Value::String("studio-a".to_string())
    );
    assert_eq!(
        payload["data"]["environments"][1]["witness_ids"],
        serde_json::json!(["w2", "w3"])
    );
}

#[tokio::test]
async fn witness_topology_reads_structured_json_config() {
    let _env = TestEnvGuard::set(&[(
        "WITNESS_CONFIG_JSON",
        r#"{"witnesses":[{"id":"w1","secret":"s1","scope":"primary","environment":"studio-a"},{"id":"w2","secret":"s2","scope":"backup","environment":"studio-b"}],"quorum":2,"scope":"cross-env"}"#,
    )]);
    let mut state = test_state();
    state.witness_service = Some(WitnessService::from_env(test_pg_pool()));
    let app = build_app(state, &test_config());

    let request = Request::builder()
        .uri("/v2/trust/witness/topology")
        .header("X-API-Key", test_master_key())
        .body(Body::empty())
        .expect("request");

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let payload: Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(
        payload["data"]["scope"],
        Value::String("cross-env".to_string())
    );
    assert_eq!(
        payload["data"]["witness_scopes"][0]["environment"],
        Value::String("studio-a".to_string())
    );
    assert_eq!(payload["data"]["quorum"], Value::Number(2.into()));
}
