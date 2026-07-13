use std::net::SocketAddr;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::core::audit_chain::AuditChain;
use crate::core::auth::AuthManager;
use crate::core::checkpoint::CheckpointService;
use crate::core::compliance::RetentionPolicy;
use crate::core::config::{AppConfig, AppEnv, LogFormat};
use crate::core::db::{migrations::run_migrations, pool::init_pg_pool_from_env};
use crate::core::events::EventStore;
use crate::core::high_risk::HighRiskGuard;
use crate::core::lock::LockManager;
use crate::core::replay::ReplayService;
use crate::core::session::SessionManager;
use crate::core::storage::StorageManager;
use crate::core::versioning::VersionManager;
use crate::core::witness::WitnessService;
use crate::routes::build_app;
use crate::state::{AppState, HttpMetrics, RateLimiter};

const VERSION: &str = "Surface 26.0.1 Preview";

fn print_banner(env: AppEnv) {
    println!();
    println!("==============================================================");
    println!(" HyperTide Backend {}", VERSION);
    println!(" Environment: {}", env.as_str());
    println!("==============================================================");
    println!();
}

pub(crate) async fn run() {
    dotenvy::dotenv().ok();

    let config = match AppConfig::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("Configuration error: {error}");
            std::process::exit(1);
        }
    };
    print_banner(config.app_env);

    let log_filter = tracing_subscriber::EnvFilter::new(
        std::env::var("RUST_LOG")
            .unwrap_or_else(|_| "hypertide_cli=info,hypertide=info,tower_http=debug".into()),
    );
    if config.log_format == LogFormat::Json {
        tracing_subscriber::registry()
            .with(log_filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(log_filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }

    tracing::info!(
        app_env = config.app_env.as_str(),
        storage_path = %config.storage_path,
        cors_allowed_origins = config.cors_allowed_origins.len(),
        rate_limit_requests_per_minute = config.rate_limit_requests_per_minute,
        log_format = config.log_format.as_str(),
        "Effective server configuration loaded"
    );

    let db_pool = match init_pg_pool_from_env().await {
        Ok(pool) => pool,
        Err(e) => {
            tracing::error!("Failed to initialize postgres pool: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = run_migrations(&db_pool).await {
        tracing::error!("Failed to run database migrations: {e}");
        std::process::exit(1);
    }
    tracing::info!("Database ready (pool + migrations)");

    let storage_manager = StorageManager::new(&config.storage_path);
    if let Err(e) = storage_manager.init().await {
        tracing::error!("Failed to initialize storage: {}", e);
        std::process::exit(1);
    }
    tracing::info!("Storage initialized at {}", &config.storage_path);

    let auth_manager =
        match AuthManager::with_dev_key_and_db(config.master_key.clone(), db_pool.clone()).await {
            Ok(manager) => manager,
            Err(e) => {
                tracing::error!("Failed to initialize auth manager: {e}");
                std::process::exit(1);
            }
        };
    let lock_manager = match LockManager::with_pg(db_pool.clone()).await {
        Ok(manager) => manager,
        Err(e) => {
            tracing::error!("Failed to initialize lock manager: {e}");
            std::process::exit(1);
        }
    };

    let version_manager = match VersionManager::with_pg(db_pool.clone()).await {
        Ok(manager) => manager,
        Err(e) => {
            tracing::error!("Failed to initialize version manager: {e}");
            std::process::exit(1);
        }
    };
    let session_manager = match SessionManager::with_pg(db_pool.clone()).await {
        Ok(manager) => manager,
        Err(e) => {
            tracing::error!("Failed to initialize session manager: {e}");
            std::process::exit(1);
        }
    };

    let state = AppState {
        lock_manager,
        storage_manager,
        auth_manager,
        version_manager,
        session_manager,
        event_store: Some(EventStore::new(db_pool.clone())),
        audit_chain: Some(AuditChain::new(db_pool.clone())),
        checkpoint_service: Some(CheckpointService::new(db_pool.clone())),
        witness_service: Some(WitnessService::from_env(db_pool.clone())),
        high_risk_guard: Some(HighRiskGuard::from_env(db_pool.clone())),
        replay_service: Some(ReplayService::new(db_pool.clone())),
        retention_policy: RetentionPolicy::from_env(),
        db_pool: Some(db_pool),
        metrics: HttpMetrics::default(),
        rate_limiter: RateLimiter::new(config.rate_limit_requests_per_minute),
    };

    let app = build_app(state, &config);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::info!("{} - listening on http://{}", VERSION, addr);

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(e) => {
            tracing::error!("Failed to bind address: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    {
        tracing::error!("Server exited with error: {e}");
        std::process::exit(1);
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!("Failed to install CTRL+C handler: {error}");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::error!("Failed to install SIGTERM handler: {error}");
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }

    tracing::info!("Shutdown signal received; draining server");
}
