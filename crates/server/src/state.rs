use axum::{extract::FromRef, http::StatusCode};
use dashmap::DashMap;
use sqlx::PgPool;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

use crate::core::audit_chain::AuditChain;
use crate::core::auth::AuthManager;
use crate::core::checkpoint::CheckpointService;
use crate::core::compliance::RetentionPolicy;
use crate::core::events::EventStore;
use crate::core::high_risk::HighRiskGuard;
use crate::core::lock::LockManager;
use crate::core::replay::ReplayService;
use crate::core::session::SessionManager;
use crate::core::storage::StorageManager;
use crate::core::versioning::VersionManager;
use crate::core::witness::WitnessService;

const LATENCY_BUCKETS_SECONDS: &[f64] = &[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0];

#[derive(Clone)]
pub struct AppState {
    pub lock_manager: LockManager,
    pub storage_manager: StorageManager,
    pub auth_manager: AuthManager,
    pub version_manager: VersionManager,
    pub session_manager: SessionManager,
    pub event_store: Option<EventStore>,
    pub audit_chain: Option<AuditChain>,
    pub checkpoint_service: Option<CheckpointService>,
    pub witness_service: Option<WitnessService>,
    pub high_risk_guard: Option<HighRiskGuard>,
    pub replay_service: Option<ReplayService>,
    pub retention_policy: RetentionPolicy,
    pub db_pool: Option<PgPool>,
    pub metrics: HttpMetrics,
    pub rate_limiter: RateLimiter,
}

#[derive(Clone, Default)]
pub struct HttpMetrics {
    requests_total: Arc<AtomicU64>,
    responses_2xx: Arc<AtomicU64>,
    responses_3xx: Arc<AtomicU64>,
    responses_4xx: Arc<AtomicU64>,
    responses_5xx: Arc<AtomicU64>,
    rate_limit_rejects: Arc<AtomicU64>,
    requests_by_label: Arc<DashMap<String, AtomicU64>>,
    latency_buckets_by_label: Arc<DashMap<String, AtomicU64>>,
    business_events_by_label: Arc<DashMap<String, AtomicU64>>,
}

impl HttpMetrics {
    pub(crate) fn record(&self, method: &str, route: &str, status: StatusCode, latency: Duration) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        let counter = match status.as_u16() {
            200..=299 => &self.responses_2xx,
            300..=399 => &self.responses_3xx,
            400..=499 => &self.responses_4xx,
            _ => &self.responses_5xx,
        };
        counter.fetch_add(1, Ordering::Relaxed);

        let status = status.as_u16().to_string();
        self.increment(
            &self.requests_by_label,
            format!(
                "method=\"{}\",route=\"{}\",status=\"{}\"",
                escape_label_value(method),
                escape_label_value(route),
                status
            ),
        );

        let elapsed = latency.as_secs_f64();
        for bucket in LATENCY_BUCKETS_SECONDS {
            if elapsed <= *bucket {
                self.increment(
                    &self.latency_buckets_by_label,
                    format!(
                        "method=\"{}\",route=\"{}\",le=\"{}\"",
                        escape_label_value(method),
                        escape_label_value(route),
                        bucket
                    ),
                );
            }
        }
        self.increment(
            &self.latency_buckets_by_label,
            format!(
                "method=\"{}\",route=\"{}\",le=\"+Inf\"",
                escape_label_value(method),
                escape_label_value(route),
            ),
        );
        self.record_business_events(route, status.as_str());
    }

    pub(crate) fn record_rate_limited(&self) {
        self.rate_limit_rejects.fetch_add(1, Ordering::Relaxed);
    }

    fn increment(&self, map: &DashMap<String, AtomicU64>, labels: String) {
        map.entry(labels)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_business_events(&self, route: &str, status: &str) {
        let mut events = Vec::new();

        if status == "401" {
            events.push("auth_failure");
        }
        if route == "/health/ready" && status == "503" {
            events.push("db_readiness_failure");
        }
        if (route.starts_with("/v2/storage") || route.starts_with("/v2/blobs"))
            && status.starts_with('5')
        {
            events.push("storage_error");
        }
        match route {
            "/v2/locks/acquire" => events.push("lock_acquire"),
            "/v2/locks/release" => events.push("lock_release"),
            "/v2/locks/renew" => events.push("lock_renew"),
            "/v2/locks/force-release" => events.push("lock_force_release"),
            "/v2/changesets" => events.push("submit"),
            _ => {}
        }
        if route.contains("checkpoints") {
            events.push("checkpoint");
        }
        if route.contains("/witness/") {
            events.push("witness");
        }
        if route.contains("/audit/") {
            events.push("audit");
        }
        if route.contains("/replay/") {
            events.push("replay");
        }

        for event in events {
            self.increment(
                &self.business_events_by_label,
                format!(
                    "event=\"{}\",status=\"{}\"",
                    escape_label_value(event),
                    escape_label_value(status)
                ),
            );
        }
    }

    pub(crate) fn render_prometheus(&self) -> String {
        let mut output = format!(
            concat!(
                "# HELP hypertide_http_requests_total Total HTTP requests handled by HyperTide.\n",
                "# TYPE hypertide_http_requests_total counter\n",
                "hypertide_http_requests_total {}\n",
                "# HELP hypertide_http_responses_total HTTP responses by status class.\n",
                "# TYPE hypertide_http_responses_total counter\n",
                "hypertide_http_responses_total{{status_class=\"2xx\"}} {}\n",
                "hypertide_http_responses_total{{status_class=\"3xx\"}} {}\n",
                "hypertide_http_responses_total{{status_class=\"4xx\"}} {}\n",
                "hypertide_http_responses_total{{status_class=\"5xx\"}} {}\n",
                "# HELP hypertide_rate_limit_rejects_total HTTP requests rejected by rate limiting.\n",
                "# TYPE hypertide_rate_limit_rejects_total counter\n",
                "hypertide_rate_limit_rejects_total {}\n",
            ),
            self.requests_total.load(Ordering::Relaxed),
            self.responses_2xx.load(Ordering::Relaxed),
            self.responses_3xx.load(Ordering::Relaxed),
            self.responses_4xx.load(Ordering::Relaxed),
            self.responses_5xx.load(Ordering::Relaxed),
            self.rate_limit_rejects.load(Ordering::Relaxed),
        );

        let mut request_lines = self
            .requests_by_label
            .iter()
            .map(|entry| {
                format!(
                    "hypertide_http_requests_total{{{}}} {}\n",
                    entry.key(),
                    entry.value().load(Ordering::Relaxed)
                )
            })
            .collect::<Vec<_>>();
        request_lines.sort();
        output.push_str(&request_lines.concat());

        output.push_str(
            "# HELP hypertide_http_request_duration_seconds HTTP request latency histogram.\n",
        );
        output.push_str("# TYPE hypertide_http_request_duration_seconds histogram\n");
        let mut latency_lines = self
            .latency_buckets_by_label
            .iter()
            .map(|entry| {
                format!(
                    "hypertide_http_request_duration_seconds_bucket{{{}}} {}\n",
                    entry.key(),
                    entry.value().load(Ordering::Relaxed)
                )
            })
            .collect::<Vec<_>>();
        latency_lines.sort();
        output.push_str(&latency_lines.concat());
        output.push_str("# HELP hypertide_business_events_total Business-domain operations and notable failures by event and status.\n");
        output.push_str("# TYPE hypertide_business_events_total counter\n");
        let mut business_lines = self
            .business_events_by_label
            .iter()
            .map(|entry| {
                format!(
                    "hypertide_business_events_total{{{}}} {}\n",
                    entry.key(),
                    entry.value().load(Ordering::Relaxed)
                )
            })
            .collect::<Vec<_>>();
        business_lines.sort();
        output.push_str(&business_lines.concat());
        output
    }
}

#[derive(Clone)]
pub struct RateLimiter {
    max_requests_per_minute: u64,
    buckets: Arc<DashMap<String, Mutex<RateLimitWindow>>>,
}

struct RateLimitWindow {
    started_at: Instant,
    used: u64,
}

impl RateLimiter {
    pub(crate) fn new(max_requests_per_minute: u64) -> Self {
        Self {
            max_requests_per_minute,
            buckets: Arc::new(DashMap::new()),
        }
    }

    pub(crate) fn allow(&self, bucket: &str) -> bool {
        if self.max_requests_per_minute == 0 {
            return true;
        }
        let entry = self.buckets.entry(bucket.to_string()).or_insert_with(|| {
            Mutex::new(RateLimitWindow {
                started_at: Instant::now(),
                used: 0,
            })
        });
        let mut window = entry.lock().expect("rate limit mutex poisoned");
        if window.started_at.elapsed() >= Duration::from_secs(60) {
            window.started_at = Instant::now();
            window.used = 0;
        }
        if window.used >= self.max_requests_per_minute {
            return false;
        }
        window.used += 1;
        true
    }
}

#[derive(Clone)]
pub(crate) struct RateLimitState {
    pub(crate) limiter: RateLimiter,
    pub(crate) metrics: HttpMetrics,
    pub(crate) auth_manager: AuthManager,
}

fn escape_label_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

impl FromRef<AppState> for LockManager {
    fn from_ref(state: &AppState) -> Self {
        state.lock_manager.clone()
    }
}

impl FromRef<AppState> for StorageManager {
    fn from_ref(state: &AppState) -> Self {
        state.storage_manager.clone()
    }
}

impl FromRef<AppState> for AuthManager {
    fn from_ref(state: &AppState) -> Self {
        state.auth_manager.clone()
    }
}

impl FromRef<AppState> for VersionManager {
    fn from_ref(state: &AppState) -> Self {
        state.version_manager.clone()
    }
}

impl FromRef<AppState> for SessionManager {
    fn from_ref(state: &AppState) -> Self {
        state.session_manager.clone()
    }
}
