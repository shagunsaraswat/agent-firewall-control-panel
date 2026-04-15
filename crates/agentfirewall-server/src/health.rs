use std::time::Duration;

use async_nats::Client as NatsClient;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use redis::aio::ConnectionManager;
use sqlx::PgPool;
use tokio::time::timeout;

#[derive(Clone)]
pub struct HealthState {
    pub pool: PgPool,
    /// When `None`, Redis-backed caching is disabled (not a readiness failure).
    pub redis: Option<ConnectionManager>,
    /// When `None`, NATS event publishing is disabled (not a readiness failure).
    pub nats: Option<NatsClient>,
}

pub fn router(state: HealthState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .with_state(state)
}

async fn healthz() -> impl IntoResponse {
    StatusCode::OK
}

async fn readyz(State(s): State<HealthState>) -> impl IntoResponse {
    const CHECK_TIMEOUT: Duration = Duration::from_secs(2);

    let db_ok = timeout(CHECK_TIMEOUT, async {
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&s.pool)
            .await
            .is_ok()
    })
    .await
    .unwrap_or(false);

    let redis_ok = match &s.redis {
        None => true,
        Some(r) => timeout(CHECK_TIMEOUT, async {
            let mut conn = r.clone();
            redis::cmd("PING")
                .query_async::<String>(&mut conn)
                .await
                .is_ok()
        })
        .await
        .unwrap_or(false),
    };

    let nats_ok = match &s.nats {
        None => true,
        Some(c) => timeout(CHECK_TIMEOUT, c.flush()).await.is_ok(),
    };

    if db_ok && redis_ok && nats_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

/// Pure logic for readiness aggregation (used in tests).
pub fn readiness_from_checks(db_ok: bool, redis_ok: bool, nats_ok: bool) -> StatusCode {
    if db_ok && redis_ok && nats_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_all_ok() {
        assert_eq!(readiness_from_checks(true, true, true), StatusCode::OK);
    }

    #[test]
    fn readiness_fails_if_any_subsystem_down() {
        assert_eq!(
            readiness_from_checks(true, false, true),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            readiness_from_checks(false, true, true),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            readiness_from_checks(true, true, false),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
