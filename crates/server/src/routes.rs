use axum::{
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit, MatchedPath, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Router,
};
use std::{net::IpAddr, net::SocketAddr, time::Instant};
use tower_http::{
    cors::{Any, CorsLayer},
    limit::RequestBodyLimitLayer,
};

use crate::api::auth::{
    exchange_key, generate_key, list_keys, refresh_token, revoke_key, revoke_refresh_token,
    verify_key,
};
use crate::api::blobs::{missing_chunks, upload_chunk};
use crate::api::lock::{force_unlock_file, list_locks, lock_file, renew_lock_file, unlock_file};
use crate::api::manifests::{compose_blob, create_manifest};
use crate::api::session::{
    checkpoint_snapshot, create_checkpoint as create_session_checkpoint, create_session,
    list_checkpoints as list_session_checkpoints, save_session,
};
use crate::api::storage::{calculate_hash, check_exists, download_file, upload_file};
use crate::api::trust::{
    attest_checkpoint, export_audit_entries, generate_checkpoint, latest_checkpoint,
    replay_readiness, retention_policy, verify_audit_chain, verify_replay, witness_summary,
    witness_topology,
};
use crate::api::versioning::{
    approve_changeset, changeset_gate, create_branch, create_repo, get_repo_info, list_branches,
    list_history, list_repos, promote_changeset, rollback, submit_changeset, sync_snapshot,
};
use crate::core::config::AppConfig;
use crate::health::{health_live, health_ready, root};
use crate::state::{AppState, HttpMetrics, RateLimitState, RateLimiter};

pub(crate) const DEFAULT_BODY_LIMIT_BYTES: usize = 2 * 1024 * 1024;
const UPLOAD_BODY_LIMIT_BYTES: usize = 256 * 1024 * 1024;

fn build_cors_layer(config: &AppConfig) -> CorsLayer {
    if config.app_env.is_production() {
        CorsLayer::new()
            .allow_origin(config.cors_allowed_origins.clone())
            .allow_methods(Any)
            .allow_headers(Any)
    } else {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
    }
}

pub(crate) fn build_app(state: AppState, config: &AppConfig) -> Router {
    let cors = build_cors_layer(config);
    let metrics = state.metrics.clone();
    let rate_limiter = RateLimiter::new(config.rate_limit_requests_per_minute);
    let rate_limit_state = RateLimitState {
        limiter: rate_limiter,
        metrics: metrics.clone(),
        auth_manager: state.auth_manager.clone(),
        trusted_proxy_cidrs: config.trusted_proxy_cidrs.clone(),
    };

    let general_routes = Router::new()
        .route("/", get(root))
        .route("/health", get(health_live))
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
        .route("/v2/locks/acquire", post(lock_file))
        .route("/v2/locks/release", post(unlock_file))
        .route("/v2/locks/renew", post(renew_lock_file))
        .route("/v2/locks/force-release", post(force_unlock_file))
        .route("/v2/locks", get(list_locks))
        .route("/v2/storage/download/:hash", get(download_file))
        .route("/v2/storage/exists/:hash", get(check_exists))
        .route("/v2/storage/hash", post(calculate_hash))
        .route("/v2/blobs/missing", post(missing_chunks))
        .route("/v2/blobs/compose", post(compose_blob))
        .route("/v2/manifests", post(create_manifest))
        .route("/v2/auth/verify", get(verify_key))
        .route("/v2/auth/generate", post(generate_key))
        .route("/v2/auth/revoke", delete(revoke_key))
        .route("/v2/auth/keys", get(list_keys))
        .route("/v2/auth/exchange-key", post(exchange_key))
        .route("/v2/auth/refresh", post(refresh_token))
        .route("/v2/auth/revoke-refresh", post(revoke_refresh_token))
        .route("/v2/repos", post(create_repo).get(list_repos))
        .route("/v2/repos/:repo_id", get(get_repo_info))
        .route("/v2/branches", post(create_branch))
        .route("/v2/branches/:repo_id", get(list_branches))
        .route("/v2/changesets", post(submit_changeset))
        .route(
            "/v2/changesets/:changeset_id/approve",
            post(approve_changeset),
        )
        .route(
            "/v2/changesets/:changeset_id/promote",
            post(promote_changeset),
        )
        .route("/v2/changesets/:changeset_id/gate", get(changeset_gate))
        .route("/v2/history/:repo_id", get(list_history))
        .route("/v2/rollback", post(rollback))
        .route("/v2/sync/:repo_id", get(sync_snapshot))
        .route("/v2/sessions", post(create_session))
        .route("/v2/sessions/:session_id/save", post(save_session))
        .route(
            "/v2/sessions/:session_id/checkpoints",
            post(create_session_checkpoint).get(list_session_checkpoints),
        )
        .route(
            "/v2/checkpoints/:checkpoint_id/snapshot",
            get(checkpoint_snapshot),
        )
        .route("/v2/trust/checkpoints/generate", post(generate_checkpoint))
        .route("/v2/trust/checkpoints/latest", get(latest_checkpoint))
        .route(
            "/v2/trust/checkpoints/:checkpoint_id/witness/attest",
            post(attest_checkpoint),
        )
        .route("/v2/trust/witness/summary", get(witness_summary))
        .route("/v2/trust/witness/topology", get(witness_topology))
        .route("/v2/trust/audit/verify", post(verify_audit_chain))
        .route("/v2/trust/audit/export", get(export_audit_entries))
        .route("/v2/trust/retention/policy", get(retention_policy))
        .route("/v2/trust/replay/verify", post(verify_replay))
        .route("/v2/trust/replay/readiness", get(replay_readiness))
        .layer(DefaultBodyLimit::max(DEFAULT_BODY_LIMIT_BYTES))
        .layer(RequestBodyLimitLayer::new(DEFAULT_BODY_LIMIT_BYTES));

    let upload_routes = Router::new()
        .route("/v2/storage/upload", post(upload_file))
        .route("/v2/blobs/chunks/:chunk_hash", put(upload_chunk))
        .layer(DefaultBodyLimit::max(UPLOAD_BODY_LIMIT_BYTES))
        .layer(RequestBodyLimitLayer::new(UPLOAD_BODY_LIMIT_BYTES));

    Router::new()
        .merge(general_routes)
        .merge(upload_routes)
        .route("/metrics", get(metrics_handler))
        .layer(middleware::from_fn_with_state(metrics, record_metrics))
        .layer(middleware::from_fn_with_state(
            rate_limit_state,
            enforce_rate_limit,
        ))
        .layer(cors)
        .with_state(state)
}

async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    (
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        state.metrics.render_prometheus(),
    )
}

async fn record_metrics(
    State(metrics): State<HttpMetrics>,
    request: axum::http::Request<Body>,
    next: Next,
) -> Response {
    let method = request.method().as_str().to_string();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_string())
        .unwrap_or_else(|| request.uri().path().to_string());
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .and_then(|value| HeaderValue::from_str(value).ok())
        .unwrap_or_else(|| HeaderValue::from_str(&uuid::Uuid::new_v4().to_string()).unwrap());
    let started_at = Instant::now();
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert("x-request-id", request_id.clone());
    metrics.record(&method, &route, response.status(), started_at.elapsed());
    response
}

async fn enforce_rate_limit(
    State(rate_limit): State<RateLimitState>,
    request: axum::http::Request<Body>,
    next: Next,
) -> Response {
    let authorization = request
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok());
    let bearer = authorization.and_then(|value| {
        let (scheme, token) = value.split_once(' ').unwrap_or((value, ""));
        scheme
            .eq_ignore_ascii_case("bearer")
            .then(|| token.trim().to_string())
    });
    let api_key = request
        .headers()
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string);
    let peer_ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|connect_info| connect_info.0.ip());
    let client_ip = resolve_client_ip(request.headers(), peer_ip, &rate_limit.trusted_proxy_cidrs);
    if (bearer.is_some() || api_key.is_some())
        && !rate_limit
            .limiter
            .allow(&ip_bucket("auth-lookup", client_ip))
    {
        rate_limit.metrics.record_rate_limited();
        return (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED").into_response();
    }
    let bucket = rate_limit_bucket(&rate_limit, bearer, api_key, client_ip).await;
    if !rate_limit.limiter.allow(&bucket) {
        rate_limit.metrics.record_rate_limited();
        return (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED").into_response();
    }
    next.run(request).await
}

fn resolve_client_ip(
    headers: &HeaderMap,
    peer_ip: Option<IpAddr>,
    trusted_proxy_cidrs: &[ipnet::IpNet],
) -> Option<IpAddr> {
    let peer_ip = peer_ip?;
    if !is_trusted_proxy(peer_ip, trusted_proxy_cidrs) {
        return Some(peer_ip);
    }

    forwarded_for_client_ip(headers, trusted_proxy_cidrs)
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.trim().parse().ok())
        })
        .or(Some(peer_ip))
}

fn forwarded_for_client_ip(
    headers: &HeaderMap,
    trusted_proxy_cidrs: &[ipnet::IpNet],
) -> Option<IpAddr> {
    let mut forwarded = Vec::new();
    for value in headers.get_all("x-forwarded-for") {
        let value = value.to_str().ok()?;
        for address in value.split(',') {
            forwarded.push(address.trim().parse::<IpAddr>().ok()?);
        }
    }
    forwarded
        .iter()
        .rev()
        .copied()
        .find(|address| !is_trusted_proxy(*address, trusted_proxy_cidrs))
        .or_else(|| forwarded.first().copied())
}

fn is_trusted_proxy(address: IpAddr, trusted_proxy_cidrs: &[ipnet::IpNet]) -> bool {
    trusted_proxy_cidrs
        .iter()
        .any(|network| network.contains(&address))
}

fn ip_bucket(prefix: &str, client_ip: Option<IpAddr>) -> String {
    client_ip
        .map(|ip| format!("{prefix}:{ip}"))
        .unwrap_or_else(|| prefix.to_string())
}

async fn rate_limit_bucket(
    rate_limit: &RateLimitState,
    bearer: Option<String>,
    api_key: Option<String>,
    peer_ip: Option<IpAddr>,
) -> String {
    if let Some(token) = bearer {
        if let Ok(identity) = rate_limit.auth_manager.validate_access_token(&token).await {
            return format!("principal:{}", identity.owner_id);
        }
    } else if let Some(api_key) = api_key {
        if let Ok(identity) = rate_limit
            .auth_manager
            .validate_api_key_identity(&api_key)
            .await
        {
            return format!("principal:{}", identity.owner_id);
        }
    }
    ip_bucket("anonymous", peer_ip)
}
