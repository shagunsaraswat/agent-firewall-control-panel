//! Request ID propagation (`X-Request-Id`) using `tower-http` plus tracing helpers.

use axum::http::header::HeaderName;
use axum::http::Request;
use tower::Layer;
pub use tower_http::request_id::{
    MakeRequestUuid, PropagateRequestId, PropagateRequestIdLayer, RequestId, SetRequestId,
    SetRequestIdLayer,
};

static X_REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

/// Composes [`SetRequestIdLayer`] (propagate incoming or generate UUID v4) with
/// [`PropagateRequestIdLayer`] (echo on the response).
///
/// Incoming clients may set `X-Request-Id`; when absent, [`MakeRequestUuid`] applies.
#[derive(Clone, Copy, Debug, Default)]
pub struct RequestIdLayer;

impl<S> Layer<S> for RequestIdLayer {
    type Service = SetRequestId<PropagateRequestId<S>, MakeRequestUuid>;

    fn layer(&self, inner: S) -> Self::Service {
        // SetRequestId must run before Propagate on the request path so a generated id exists
        // when Propagate captures it for the response.
        let inner = PropagateRequestIdLayer::x_request_id().layer(inner);
        SetRequestIdLayer::x_request_id(MakeRequestUuid).layer(inner)
    }
}

/// Build a tracing span that includes the resolved request id from request extensions / headers.
///
/// Apply [`RequestIdLayer`] (or [`SetRequestIdLayer`]) *before* [`tower_http::trace::TraceLayer`]
/// so the id is present when this runs inside `make_span_with`.
pub fn trace_span_with_request_id<B>(req: &Request<B>) -> tracing::Span {
    let rid = req
        .extensions()
        .get::<tower_http::request_id::RequestId>()
        .and_then(|r| r.header_value().to_str().ok())
        .or_else(|| {
            req.headers()
                .get(&X_REQUEST_ID_HEADER)
                .and_then(|v| v.to_str().ok())
        })
        .unwrap_or("-");
    tracing::info_span!("request", request_id = %rid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::{ServiceBuilder, ServiceExt};

    #[tokio::test]
    async fn propagates_incoming_request_id() {
        let svc = ServiceBuilder::new().layer(RequestIdLayer).service_fn(
            |req: Request<Body>| async move {
                let id = req
                    .extensions()
                    .get::<RequestId>()
                    .and_then(|r| r.header_value().to_str().ok())
                    .unwrap_or("")
                    .to_string();
                Ok::<_, std::convert::Infallible>(axum::response::Response::new(Body::from(id)))
            },
        );

        let res = svc
            .oneshot(
                Request::builder()
                    .header("x-request-id", "client-req-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.headers()["x-request-id"], "client-req-1");
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"client-req-1");
    }

    #[tokio::test]
    async fn generates_uuid_when_missing() {
        let svc = ServiceBuilder::new().layer(RequestIdLayer).service_fn(
            |req: Request<Body>| async move {
                let id = req
                    .extensions()
                    .get::<RequestId>()
                    .and_then(|r| r.header_value().to_str().ok())
                    .unwrap_or("")
                    .to_string();
                Ok::<_, std::convert::Infallible>(axum::response::Response::new(Body::from(id)))
            },
        );

        let res = svc
            .oneshot(Request::builder().body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let id = std::str::from_utf8(&body).expect("utf8 body");
        uuid::Uuid::parse_str(id).expect("uuid v4 string");
    }
}
