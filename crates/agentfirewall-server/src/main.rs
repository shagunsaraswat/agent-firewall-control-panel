use std::time::Duration;

use agentfirewall_server::auth::{ApiKeyAuth, AuthInterceptor, AuthLayer};
use agentfirewall_server::config::ServerConfig;
use agentfirewall_server::db;
use agentfirewall_server::health::{self, HealthState};
use agentfirewall_server::metrics::{self, HttpMetricsState, MetricsState};
use agentfirewall_server::nats::NatsPublisher;
use agentfirewall_server::proto::{
    ApprovalServiceServer, IncidentServiceServer, LearnerServiceServer, PolicyServiceServer,
    RunServiceServer,
};
use agentfirewall_server::request_id::RequestIdLayer;
use agentfirewall_server::rest::{self, AppState};
use agentfirewall_server::services::approval::{self, ApprovalServiceImpl};
use agentfirewall_server::services::baseline;
use agentfirewall_server::services::incident::IncidentServiceImpl;
use agentfirewall_server::services::learner::LearnerServiceImpl;
use agentfirewall_server::services::policy::PolicyServiceImpl;
use agentfirewall_server::services::run::RunServiceImpl;
use agentfirewall_server::services::span_ingest;
use agentfirewall_server::services::webhook::WebhookDispatcher;
use axum::http::HeaderValue;
use axum::middleware;
use axum::Router;
use redis::Client as RedisClient;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tonic::transport::Server;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    let config = ServerConfig::from_env()?;
    tracing::info!(
        http_listen = %config.listen_addr,
        grpc = %config.grpc_addr,
        metrics_addr = %config.metrics_addr,
        "Agent FirewallKit server starting"
    );

    let pool = db::create_pool(&config).await?;
    db::run_migrations(&pool).await?;

    let redis_mgr = match RedisClient::open(config.redis_url.as_str()) {
        Ok(client) => match redis::aio::ConnectionManager::new(client).await {
            Ok(mgr) => {
                tracing::info!("connected to Redis");
                Some(mgr)
            }
            Err(e) => {
                tracing::warn!(error = %e, "Redis unavailable; caching and Redis-backed features degraded");
                None
            }
        },
        Err(e) => {
            tracing::warn!(error = %e, "invalid Redis URL; caching disabled");
            None
        }
    };

    let nats_client = match async_nats::connect(config.nats_url.as_str()).await {
        Ok(c) => {
            tracing::info!("connected to NATS");
            Some(c)
        }
        Err(e) => {
            tracing::warn!(error = %e, "NATS unavailable; event publishing disabled where optional");
            None
        }
    };

    let clickhouse_ok = clickhouse_reachable(&config.clickhouse_url).await;
    if !clickhouse_ok {
        tracing::warn!(
            url = %config.clickhouse_url,
            "ClickHouse not reachable; span ingest and baseline aggregation disabled"
        );
    }

    let nats_pub = nats_client.as_ref().map(|c| NatsPublisher::new(c.clone()));

    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.request_timeout_secs))
        .build()?;

    let webhooks = WebhookDispatcher::new(pool.clone(), http_client);
    let api_key_auth = ApiKeyAuth::new(pool.clone());

    let idem_ttl = config.idempotency_ttl_secs;
    let policy_impl = PolicyServiceImpl::new(pool.clone(), idem_ttl);
    let run_impl = RunServiceImpl::new(pool.clone(), idem_ttl);
    let approval_impl =
        ApprovalServiceImpl::new(pool.clone(), nats_pub.clone(), webhooks.clone(), idem_ttl);
    let incident_impl =
        IncidentServiceImpl::new(pool.clone(), nats_pub.clone(), webhooks.clone(), idem_ttl);
    let learner_impl = LearnerServiceImpl::new(pool.clone(), redis_mgr.clone(), nats_pub.clone());

    let auth_interceptor = AuthInterceptor::new(api_key_auth.clone(), None);
    let policy_svc =
        PolicyServiceServer::with_interceptor(policy_impl.clone(), auth_interceptor.clone());
    let run_svc = RunServiceServer::with_interceptor(run_impl.clone(), auth_interceptor.clone());
    let approval_svc =
        ApprovalServiceServer::with_interceptor(approval_impl.clone(), auth_interceptor.clone());
    let incident_svc =
        IncidentServiceServer::with_interceptor(incident_impl.clone(), auth_interceptor.clone());
    let learner_svc =
        LearnerServiceServer::with_interceptor(learner_impl.clone(), auth_interceptor.clone());

    let prom_handle = metrics::install_metrics()?;
    let metrics_state = MetricsState {
        handle: prom_handle.clone(),
        pool: pool.clone(),
    };

    let (span_task, span_shutdown) = if clickhouse_ok {
        match nats_client.clone() {
            Some(nc) => {
                let (h, s) = span_ingest::start_with_shutdown(nc, config.clickhouse_url.clone());
                (Some(h), Some(s))
            }
            None => {
                tracing::warn!("span ingest not started: NATS not available");
                (None, None)
            }
        }
    } else {
        (None, None)
    };

    let baseline_task = match (&redis_mgr, clickhouse_ok) {
        (Some(r), true) => Some(baseline::start(
            pool.clone(),
            r.clone(),
            config.clickhouse_url.clone(),
            Duration::from_secs(300),
        )),
        (None, true) => {
            tracing::warn!("baseline aggregator not started: Redis not available");
            None
        }
        (_, false) => None,
    };

    let approval_expiry_task = tokio::spawn(approval::run_expiry_loop(
        pool.clone(),
        Duration::from_secs(60),
    ));

    let shutdown = std::sync::Arc::new(Notify::new());
    let shutdown_http = shutdown.clone();
    let span_shutdown_for_signal = span_shutdown.clone();
    tokio::spawn(async move {
        wait_shutdown_signal().await;
        tracing::info!("shutdown signal received; stopping listeners and flushing work");
        if let Some(s) = span_shutdown_for_signal {
            s.signal();
        }
        shutdown_http.notify_waiters();
    });

    let mut grpc_builder = Server::builder();
    if let (Some(cert_path), Some(key_path)) = (&config.tls_cert_path, &config.tls_key_path) {
        let cert = tokio::fs::read(cert_path).await?;
        let key = tokio::fs::read(key_path).await?;
        let identity = tonic::transport::Identity::from_pem(cert, key);
        let tls = tonic::transport::ServerTlsConfig::new().identity(identity);
        grpc_builder = grpc_builder.tls_config(tls)?;
    }
    let grpc_builder = grpc_builder
        .add_service(policy_svc)
        .add_service(run_svc)
        .add_service(approval_svc)
        .add_service(incident_svc)
        .add_service(learner_svc);

    let grpc_addr = config.grpc_addr;
    let grpc_shutdown = shutdown.clone();
    let grpc_task = tokio::spawn(async move {
        grpc_builder
            .serve_with_shutdown(grpc_addr, async move {
                grpc_shutdown.notified().await;
            })
            .await
            .map_err(|e| anyhow::anyhow!(e))
    });

    let cors = build_cors_layer(&config)?;
    let cors_metrics = cors.clone();

    let health_state = HealthState {
        pool: pool.clone(),
        redis: redis_mgr.clone(),
        nats: nats_client.clone(),
    };
    let http_metrics_state = HttpMetricsState { pool: pool.clone() };

    let mut protected = Router::new();
    if config.http_api_enabled {
        let app_state = AppState {
            pool: pool.clone(),
            policy_svc: policy_impl,
            run_svc: run_impl,
            approval_svc: approval_impl,
            incident_svc: incident_impl,
            learner_svc: learner_impl,
        };
        protected = protected.merge(rest::router(app_state));
    }
    protected = protected.layer(AuthLayer::new(api_key_auth));
    let http_app = Router::new()
        .merge(health::router(health_state))
        .merge(metrics::metrics_router(metrics_state))
        .merge(protected)
        .layer(middleware::from_fn_with_state(
            http_metrics_state,
            metrics::track_http_metrics,
        ))
        .layer(cors)
        .layer(RequestIdLayer);

    let http_listener = TcpListener::bind(config.listen_addr).await?;
    let http_shutdown = shutdown.clone();
    let http_task = tokio::spawn(async move {
        axum::serve(http_listener, http_app)
            .with_graceful_shutdown(async move {
                http_shutdown.notified().await;
            })
            .await
            .map_err(|e| anyhow::anyhow!(e))
    });

    let metrics_scrape_task = if config.metrics_addr != config.listen_addr {
        let metrics_only = metrics::metrics_router(MetricsState {
            handle: prom_handle.clone(),
            pool: pool.clone(),
        })
        .layer(middleware::from_fn_with_state(
            HttpMetricsState { pool: pool.clone() },
            metrics::track_http_metrics,
        ))
        .layer(cors_metrics)
        .layer(RequestIdLayer);
        let ml = TcpListener::bind(config.metrics_addr).await?;
        let ms = shutdown.clone();
        Some(tokio::spawn(async move {
            axum::serve(ml, metrics_only)
                .with_graceful_shutdown(async move {
                    ms.notified().await;
                })
                .await
                .map_err(|e| anyhow::anyhow!(e))
        }))
    } else {
        None
    };

    match metrics_scrape_task {
        None => {
            let (grpc_res, http_res) = tokio::try_join!(grpc_task, http_task)?;
            grpc_res?;
            http_res?;
        }
        Some(metrics_task) => {
            let (grpc_res, http_res, metrics_res) =
                tokio::try_join!(grpc_task, http_task, metrics_task)?;
            grpc_res?;
            http_res?;
            metrics_res?;
        }
    }

    tracing::info!("HTTP and gRPC listeners stopped");

    approval_expiry_task.abort();
    let _ = approval_expiry_task.await;

    if let Some(t) = baseline_task {
        t.abort();
        let _ = t.await;
    }

    const SPAN_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
    if let Some(h) = span_task {
        match tokio::time::timeout(SPAN_DRAIN_TIMEOUT, h).await {
            Ok(Ok(())) => tracing::debug!("span ingest task finished"),
            Ok(Err(e)) => tracing::warn!(error = %e, "span ingest task join error"),
            Err(_) => tracing::warn!("span ingest flush timed out"),
        }
    }

    if let Some(nc) = nats_client {
        if let Err(e) = nc.flush().await {
            tracing::warn!(error = %e, "NATS flush during shutdown failed");
        }
    }

    pool.close().await;

    tracing::info!("Agent FirewallKit shutdown complete");
    Ok(())
}

async fn wait_shutdown_signal() {
    tokio::select! {
        _ = async {
            let _ = tokio::signal::ctrl_c().await;
        } => {
            tracing::info!("received SIGINT");
        },
        _ = async {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                if let Ok(mut s) = signal(SignalKind::terminate()) {
                    let _ = s.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            }
            #[cfg(not(unix))]
            {
                std::future::pending::<()>().await;
            }
        } => {
            tracing::info!("received SIGTERM");
        },
    }
}

async fn clickhouse_reachable(base_url: &str) -> bool {
    let base = base_url.trim_end_matches('/');
    if base.is_empty() {
        return false;
    }
    let url = format!("{base}/");
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    client
        .get(url)
        .query(&[("query", "SELECT 1")])
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

fn build_cors_layer(config: &ServerConfig) -> anyhow::Result<CorsLayer> {
    if config.cors_origins.len() == 1 && config.cors_origins[0] == "*" {
        return Ok(CorsLayer::permissive());
    }
    let mut origins = Vec::with_capacity(config.cors_origins.len());
    for o in &config.cors_origins {
        origins.push(
            o.parse::<HeaderValue>()
                .map_err(|e| anyhow::anyhow!("invalid CORS origin {o:?}: {e}"))?,
        );
    }
    Ok(CorsLayer::new().allow_origin(AllowOrigin::list(origins)))
}
