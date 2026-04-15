use std::time::Instant;

use axum::extract::Request;
use axum::extract::State;
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use sqlx::PgPool;

#[derive(Clone)]
pub struct MetricsState {
    pub handle: PrometheusHandle,
    pub pool: PgPool,
}

pub fn install_metrics() -> anyhow::Result<PrometheusHandle> {
    describe_counter!(
        "agentfirewall_request_count",
        "Total HTTP requests served on this listener"
    );
    describe_histogram!(
        "agentfirewall_request_duration_seconds",
        "HTTP request duration in seconds"
    );
    describe_gauge!(
        "agentfirewall_active_connections",
        "Approximate in-use database pool connections (size - idle)"
    );
    describe_gauge!(
        "agentfirewall_db_pool_size",
        "Total connections in the SQLx pool"
    );

    let handle = PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Full("agentfirewall_request_duration_seconds".to_string()),
            &[
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ],
        )?
        .install_recorder()?;

    Ok(handle)
}

pub fn metrics_router(state: MetricsState) -> Router {
    Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(state)
}

async fn metrics_handler(State(state): State<MetricsState>) -> impl IntoResponse {
    refresh_pool_gauges(&state.pool);
    state.handle.render()
}

fn refresh_pool_gauges(pool: &PgPool) {
    let size = pool.size();
    let idle = pool.num_idle();
    let active = size.saturating_sub(idle as u32);
    gauge!("agentfirewall_db_pool_size").set(size as f64);
    gauge!("agentfirewall_active_connections").set(active as f64);
}

#[derive(Clone)]
pub struct HttpMetricsState {
    pub pool: PgPool,
}

pub async fn track_http_metrics(
    State(state): State<HttpMetricsState>,
    req: Request,
    next: Next,
) -> impl IntoResponse {
    refresh_pool_gauges(&state.pool);
    let start = Instant::now();
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let res = next.run(req).await;
    let status = res.status().as_u16().to_string();
    let elapsed = start.elapsed().as_secs_f64();
    counter!(
        "agentfirewall_request_count",
        "method" => method.to_string(),
        "path" => path.clone(),
        "status" => status
    )
    .increment(1);
    histogram!(
        "agentfirewall_request_duration_seconds",
        "method" => method.to_string(),
        "path" => path
    )
    .record(elapsed);
    res
}
