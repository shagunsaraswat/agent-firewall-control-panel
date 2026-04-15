use super::types::{AuthContext, AuthError};
use axum::http::{Request, Response};
use pin_project_lite::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Tenant isolation helpers for SQL and resource checks.
pub struct TenantScope;

impl TenantScope {
    /// Returns `tenant_id` for `WHERE tenant_id = $1` style scoping.
    pub fn tenant_filter(ctx: &AuthContext) -> &str {
        ctx.tenant_id.as_str()
    }

    /// Ensures a loaded resource belongs to the authenticated tenant.
    pub fn validate_resource_ownership(
        ctx: &AuthContext,
        resource_tenant_id: &str,
    ) -> Result<(), AuthError> {
        if ctx.tenant_id == resource_tenant_id {
            Ok(())
        } else {
            Err(AuthError::Internal("tenant_mismatch".to_string()))
        }
    }
}

/// Typed extension: resolved tenant id (mirrors [`AuthContext::tenant_id`] after auth).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantId(pub String);

/// Tower layer that exposes [`TenantId`] in request extensions when [`AuthContext`] is present.
#[derive(Clone, Copy, Debug, Default)]
pub struct TenantMiddleware;

impl<S> tower::Layer<S> for TenantMiddleware {
    type Service = TenantService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TenantService { inner }
    }
}

#[derive(Clone)]
pub struct TenantService<S> {
    inner: S,
}

impl<S, ReqBody, ResBody> tower::Service<Request<ReqBody>> for TenantService<S>
where
    S: tower::Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = TenantFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        if let Some(ctx) = req.extensions().get::<AuthContext>().cloned() {
            let tid = TenantScope::tenant_filter(&ctx).to_string();
            req.extensions_mut().insert(TenantId(tid));
        }
        TenantFuture {
            inner: self.inner.call(req),
        }
    }
}

pin_project! {
    pub struct TenantFuture<F> {
        #[pin]
        inner: F,
    }
}

impl<F, T, E> Future for TenantFuture<F>
where
    F: Future<Output = Result<T, E>>,
{
    type Output = Result<T, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().inner.poll(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    use crate::auth::types::{Permission, PrincipalType};
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::{Layer, Service};

    fn ctx(tenant: &str) -> AuthContext {
        AuthContext {
            tenant_id: tenant.to_string(),
            principal_id: "k1".to_string(),
            principal_type: PrincipalType::ApiKey,
            permissions: HashSet::from([Permission::PolicyRead]),
        }
    }

    #[test]
    fn tenant_filter_returns_id() {
        let c = ctx("550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(
            TenantScope::tenant_filter(&c),
            "550e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[test]
    fn validate_resource_ownership_ok() {
        let c = ctx("t1");
        assert!(TenantScope::validate_resource_ownership(&c, "t1").is_ok());
    }

    #[test]
    fn validate_resource_ownership_err() {
        let c = ctx("t1");
        let e = TenantScope::validate_resource_ownership(&c, "t2").unwrap_err();
        match e {
            AuthError::Internal(m) => assert_eq!(m, "tenant_mismatch"),
            _ => panic!("unexpected {e:?}"),
        }
    }

    #[tokio::test]
    async fn tenant_middleware_sets_extension() {
        let inner = tower::service_fn(|req: Request<Body>| async move {
            let tid = req
                .extensions()
                .get::<TenantId>()
                .cloned()
                .expect("tenant id");
            Ok::<_, std::convert::Infallible>(Response::new(Body::from(tid.0)))
        });
        let mut svc = TenantMiddleware::default().layer(inner);
        let mut req = Request::builder().body(Body::empty()).unwrap();
        req.extensions_mut().insert(ctx("tenant-a"));

        let res = svc.call(req).await.unwrap();
        let bytes = BodyExt::collect(res.into_body()).await.unwrap().to_bytes();
        assert_eq!(&bytes[..], b"tenant-a");
    }
}
