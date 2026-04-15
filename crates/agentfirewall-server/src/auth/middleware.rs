use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use super::api_key::ApiKeyAuth;
use super::types::{AuthContext, AuthError, Permission};
use crate::request_id::RequestId;
use crate::rest::error::ErrorEnvelope;
use axum::body::Body;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, Request, Response, StatusCode};

/// Enforces that `ctx` includes `perm` or [`Permission::Admin`].
pub fn require_permission(ctx: &AuthContext, perm: Permission) -> Result<(), AuthError> {
    if ctx.permissions.contains(&Permission::Admin) || ctx.permissions.contains(&perm) {
        Ok(())
    } else {
        Err(AuthError::InsufficientPermissions {
            required: perm,
            actual: ctx.permissions.clone(),
        })
    }
}

pub fn extract_http_api_key(headers: &HeaderMap) -> Option<&str> {
    const BEARER: &str = "Bearer ";
    if let Some(v) = headers
        .get(axum::http::HeaderName::from_static("x-api-key"))
        .and_then(|h| h.to_str().ok())
    {
        let t = v.trim();
        if !t.is_empty() {
            return Some(t);
        }
    }
    if let Some(v) = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok()) {
        let v = v.trim();
        if v.len() > BEARER.len() && v[..BEARER.len()].eq_ignore_ascii_case(BEARER) {
            let t = v[BEARER.len()..].trim();
            if !t.is_empty() {
                return Some(t);
            }
        }
    }
    None
}

pub fn extract_grpc_api_key(meta: &tonic::metadata::MetadataMap) -> Option<String> {
    meta.get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// Reads `X-Request-Id` when [`crate::request_id::RequestIdLayer`] (or equivalent) has run
/// before auth. Production HTTP stack applies `RequestIdLayer` as the outermost layer, so auth
/// failures include `request_id` in the JSON body for correlation. Routers without that layer
/// omit the field (`serde` skips `None`), matching [`ErrorEnvelope`] usage elsewhere.
fn request_id_from_extensions<B>(req: &Request<B>) -> Option<String> {
    req.extensions()
        .get::<RequestId>()
        .and_then(|r| r.header_value().to_str().ok())
        .map(str::to_string)
}

fn json_error_response(
    status: StatusCode,
    code: &str,
    message: &str,
    request_id: Option<String>,
) -> Response<Body> {
    let mut envelope = ErrorEnvelope::new(code, message);
    envelope.error.request_id = request_id;
    let body = serde_json::to_string(&envelope).unwrap_or_else(|_| {
        r#"{"error":{"code":"INTERNAL_ERROR","message":"serialization failed"}}"#.to_string()
    });
    Response::builder()
        .status(status)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap()
        })
}

fn unauthorized_response(request_id: Option<String>) -> Response<Body> {
    json_error_response(
        StatusCode::UNAUTHORIZED,
        "AUTH_INVALID_CREDENTIALS",
        "Invalid credentials.",
        request_id,
    )
}

fn forbidden_response(request_id: Option<String>) -> Response<Body> {
    json_error_response(
        StatusCode::FORBIDDEN,
        "PERMISSION_DENIED",
        "Permission denied.",
        request_id,
    )
}

fn internal_server_response(request_id: Option<String>) -> Response<Body> {
    json_error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "INTERNAL_ERROR",
        "Internal error.",
        request_id,
    )
}

async fn authenticate_http_request<ReqBody>(
    auth: &ApiKeyAuth,
    required: Option<Permission>,
    mut req: Request<ReqBody>,
) -> Result<Request<ReqBody>, Response<Body>> {
    let request_id = request_id_from_extensions(&req);

    let Some(key) = extract_http_api_key(req.headers()).map(|s| s.to_string()) else {
        return Err(unauthorized_response(request_id));
    };

    let ctx = match auth.validate(&key).await {
        Ok(c) => c,
        Err(e) if e.is_credential_failure() => return Err(unauthorized_response(request_id)),
        Err(AuthError::Internal(_)) => return Err(internal_server_response(request_id)),
        Err(_) => return Err(unauthorized_response(request_id)),
    };

    if let Some(p) = required {
        require_permission(&ctx, p).map_err(|_| forbidden_response(request_id))?;
    }

    req.extensions_mut().insert(ctx);
    Ok(req)
}

/// Tower [`Layer`](tower::Layer) for Axum (HTTP): validates API keys and inserts [`AuthContext`].
#[derive(Clone)]
pub struct AuthLayer {
    auth: ApiKeyAuth,
    required: Option<Permission>,
}

impl AuthLayer {
    pub fn new(auth: ApiKeyAuth) -> Self {
        Self {
            auth,
            required: None,
        }
    }

    pub fn with_required_permission(mut self, perm: Permission) -> Self {
        self.required = Some(perm);
        self
    }
}

impl<S> tower::Layer<S> for AuthLayer {
    type Service = AuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            inner,
            auth: self.auth.clone(),
            required: self.required,
        }
    }
}

#[derive(Clone)]
pub struct AuthService<S> {
    inner: S,
    auth: ApiKeyAuth,
    required: Option<Permission>,
}

impl<S, ReqBody> tower::Service<Request<ReqBody>> for AuthService<S>
where
    S: tower::Service<Request<ReqBody>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let mut inner = self.inner.clone();
        let auth = self.auth.clone();
        let required = self.required;
        Box::pin(async move {
            let req = match authenticate_http_request(&auth, required, req).await {
                Ok(r) => r,
                Err(resp) => return Ok(resp),
            };
            inner.call(req).await
        })
    }
}

/// gRPC [`Interceptor`](tonic::service::Interceptor): validates `x-api-key` metadata and inserts [`AuthContext`].
///
/// Runs async validation via [`tokio::task::block_in_place`] + [`tokio::runtime::Handle::block_on`];
/// use a multi-thread Tokio runtime (default) to avoid deadlocks.
#[derive(Clone)]
pub struct AuthInterceptor {
    auth: std::sync::Arc<ApiKeyAuth>,
    required: Option<Permission>,
}

impl AuthInterceptor {
    pub fn new(auth: ApiKeyAuth, required: Option<Permission>) -> Self {
        Self {
            auth: std::sync::Arc::new(auth),
            required,
        }
    }
}

impl tonic::service::Interceptor for AuthInterceptor {
    fn call(&mut self, mut req: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
        let Some(key) = extract_grpc_api_key(req.metadata()) else {
            return Err(tonic::Status::unauthenticated("invalid credentials"));
        };

        let ctx = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.auth.validate(&key))
        });

        let ctx = match ctx {
            Ok(c) => c,
            Err(e) if e.is_credential_failure() => {
                return Err(tonic::Status::unauthenticated("invalid credentials"));
            }
            Err(AuthError::Internal(_)) => return Err(tonic::Status::internal("internal error")),
            Err(_) => return Err(tonic::Status::unauthenticated("invalid credentials")),
        };

        if let Some(p) = self.required {
            if require_permission(&ctx, p).is_err() {
                return Err(tonic::Status::permission_denied("permission denied"));
            }
        }

        req.extensions_mut().insert(ctx);
        Ok(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    use axum::http::StatusCode;
    use axum::routing::get;
    use axum::Router;
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use uuid::Uuid;

    use crate::auth::types::PrincipalType;

    #[test]
    fn require_permission_admin_bypass() {
        let ctx = AuthContext {
            tenant_id: "t".into(),
            principal_id: "p".into(),
            principal_type: PrincipalType::ApiKey,
            permissions: HashSet::from([Permission::Admin]),
        };
        assert!(require_permission(&ctx, Permission::PolicyWrite).is_ok());
    }

    #[test]
    fn require_permission_denied() {
        let ctx = AuthContext {
            tenant_id: "t".into(),
            principal_id: "p".into(),
            principal_type: PrincipalType::ApiKey,
            permissions: HashSet::from([Permission::PolicyRead]),
        };
        let e = require_permission(&ctx, Permission::PolicyWrite).unwrap_err();
        assert!(matches!(
            e,
            AuthError::InsufficientPermissions {
                required: Permission::PolicyWrite,
                ..
            }
        ));
    }

    #[test]
    fn extract_bearer_token() {
        let mut map = HeaderMap::new();
        map.insert(
            AUTHORIZATION,
            axum::http::HeaderValue::from_static("Bearer secret_token_value"),
        );
        assert_eq!(extract_http_api_key(&map), Some("secret_token_value"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn auth_layer_401_without_key() {
        let app = Router::new()
            .route("/x", get(|| async move { "ok" }))
            .layer(AuthLayer::new(ApiKeyAuth::new(
                sqlx::PgPool::connect_lazy("postgres://127.0.0.1:5432/postgres").unwrap(),
            )));

        let res = app
            .oneshot(Request::builder().uri("/x").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn grpc_interceptor_rejects_missing_key() {
        let pool = sqlx::PgPool::connect_lazy("postgres://127.0.0.1:5432/postgres").unwrap();
        let mut i = AuthInterceptor::new(ApiKeyAuth::new(pool), None);
        let req = tonic::Request::new(());
        let err = tonic::service::Interceptor::call(&mut i, req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn grpc_interceptor_accepts_key_with_pool() {
        let url = match std::env::var("DATABASE_URL") {
            Ok(u) => u,
            Err(_) => {
                eprintln!("skip grpc_interceptor_accepts_key_with_pool: DATABASE_URL");
                return;
            }
        };
        let pool = sqlx::PgPool::connect(&url).await.expect("pool");
        sqlx::migrate!("../../migrations/postgres")
            .run(&pool)
            .await
            .expect("migrate");

        let tenant = Uuid::new_v4().to_string();
        let raw_key = format!("av_test_{}", Uuid::new_v4());
        let hash = ApiKeyAuth::hash_key(&raw_key);
        let prefix: String = raw_key.chars().take(8).collect();

        sqlx::query(
            r#"
            INSERT INTO api_keys (tenant_id, name, key_hash, key_prefix, permissions)
            VALUES ($1, 'int', $2, $3, ARRAY['PolicyRead']::text[])
            "#,
        )
        .bind(&tenant)
        .bind(&hash[..])
        .bind(&prefix)
        .execute(&pool)
        .await
        .expect("insert");

        let mut req = tonic::Request::new(());
        req.metadata_mut()
            .insert("x-api-key", raw_key.parse().expect("metadata value"));

        let mut i = AuthInterceptor::new(ApiKeyAuth::new(pool.clone()), None);
        let out = tonic::service::Interceptor::call(&mut i, req).expect("ok");
        let ctx = out.extensions().get::<AuthContext>().expect("ctx");
        assert_eq!(ctx.tenant_id, tenant);

        sqlx::query("DELETE FROM api_keys WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .ok();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn auth_layer_integration_with_db() {
        let url = match std::env::var("DATABASE_URL") {
            Ok(u) => u,
            Err(_) => {
                eprintln!("skip auth_layer_integration_with_db: DATABASE_URL");
                return;
            }
        };
        let pool = sqlx::PgPool::connect(&url).await.expect("pool");
        sqlx::migrate!("../../migrations/postgres")
            .run(&pool)
            .await
            .expect("migrate");

        let tenant = Uuid::new_v4().to_string();
        let raw_key = format!("av_test_{}", Uuid::new_v4());
        let hash = ApiKeyAuth::hash_key(&raw_key);
        let prefix: String = raw_key.chars().take(8).collect();

        sqlx::query(
            r#"
            INSERT INTO api_keys (tenant_id, name, key_hash, key_prefix, permissions)
            VALUES ($1, 'layer', $2, $3, ARRAY['PolicyRead','PolicyWrite']::text[])
            "#,
        )
        .bind(&tenant)
        .bind(&hash[..])
        .bind(&prefix)
        .execute(&pool)
        .await
        .expect("insert");

        let make_app = || {
            Router::new()
                .route(
                    "/x",
                    get(
                        |axum::Extension(ctx): axum::Extension<AuthContext>| async move {
                            ctx.tenant_id
                        },
                    ),
                )
                .layer(
                    AuthLayer::new(ApiKeyAuth::new(pool.clone()))
                        .with_required_permission(Permission::PolicyRead),
                )
        };

        let res = make_app()
            .oneshot(
                Request::builder()
                    .uri("/x")
                    .header("X-Api-Key", &raw_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), tenant.as_bytes());

        let res = make_app()
            .oneshot(
                Request::builder()
                    .uri("/x")
                    .header("X-Api-Key", "av_test_wrong________________________________")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        sqlx::query("DELETE FROM api_keys WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .ok();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn auth_layer_403_insufficient_permission() {
        let url = match std::env::var("DATABASE_URL") {
            Ok(u) => u,
            Err(_) => {
                eprintln!("skip auth_layer_403_insufficient_permission: DATABASE_URL");
                return;
            }
        };
        let pool = sqlx::PgPool::connect(&url).await.expect("pool");
        sqlx::migrate!("../../migrations/postgres")
            .run(&pool)
            .await
            .expect("migrate");

        let tenant = Uuid::new_v4().to_string();
        let raw_key = format!("av_test_{}", Uuid::new_v4());
        let hash = ApiKeyAuth::hash_key(&raw_key);
        let prefix: String = raw_key.chars().take(8).collect();

        sqlx::query(
            r#"
            INSERT INTO api_keys (tenant_id, name, key_hash, key_prefix, permissions)
            VALUES ($1, 'layer2', $2, $3, ARRAY['PolicyRead']::text[])
            "#,
        )
        .bind(&tenant)
        .bind(&hash[..])
        .bind(&prefix)
        .execute(&pool)
        .await
        .expect("insert");

        let app = Router::new()
            .route("/x", get(|| async move { "ok" }))
            .layer(
                AuthLayer::new(ApiKeyAuth::new(pool.clone()))
                    .with_required_permission(Permission::Admin),
            );

        let res = app
            .oneshot(
                Request::builder()
                    .uri("/x")
                    .header("X-Api-Key", &raw_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        sqlx::query("DELETE FROM api_keys WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .ok();
    }
}
