use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use tonic::metadata::MetadataValue;

use crate::auth::AuthContext;
use crate::proto::common_v1::{Labels, PageResponse, ResourceScope, ScopeType};

use super::error::error_response;

pub fn make_grpc_request<T>(ctx: AuthContext, inner: T) -> tonic::Request<T> {
    let mut req = tonic::Request::new(inner);
    req.extensions_mut().insert(ctx);
    req
}

pub fn make_grpc_request_with_idempotency<T>(
    ctx: AuthContext,
    inner: T,
    idempotency_key: Option<&str>,
) -> tonic::Request<T> {
    let mut req = tonic::Request::new(inner);
    req.extensions_mut().insert(ctx);
    if let Some(key) = idempotency_key {
        if let Ok(val) = MetadataValue::try_from(key) {
            req.metadata_mut().insert("x-idempotency-key", val);
        }
    }
    req
}

pub fn status_to_rest_error(status: tonic::Status) -> Response {
    let (http_status, code) = match status.code() {
        tonic::Code::NotFound => (StatusCode::NOT_FOUND, "NOT_FOUND"),
        tonic::Code::InvalidArgument => (StatusCode::BAD_REQUEST, "INVALID_ARGUMENT"),
        tonic::Code::AlreadyExists => (StatusCode::CONFLICT, "ALREADY_EXISTS"),
        tonic::Code::FailedPrecondition => {
            (StatusCode::PRECONDITION_FAILED, "FAILED_PRECONDITION")
        }
        tonic::Code::PermissionDenied => (StatusCode::FORBIDDEN, "PERMISSION_DENIED"),
        tonic::Code::Unauthenticated => (StatusCode::UNAUTHORIZED, "UNAUTHENTICATED"),
        tonic::Code::Unimplemented => (StatusCode::NOT_IMPLEMENTED, "NOT_IMPLEMENTED"),
        tonic::Code::ResourceExhausted => (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED"),
        tonic::Code::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "UNAVAILABLE"),
        tonic::Code::Aborted => (StatusCode::CONFLICT, "CONFLICT"),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR"),
    };
    error_response(http_status, code, status.message())
}

pub fn ok_json(data: serde_json::Value) -> Response {
    (StatusCode::OK, Json(data)).into_response()
}

pub fn created_json(data: serde_json::Value) -> Response {
    (StatusCode::CREATED, Json(data)).into_response()
}

pub fn timestamp_to_string(ts: &prost_types::Timestamp) -> String {
    chrono::DateTime::from_timestamp(ts.seconds, ts.nanos as u32)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .unwrap_or_default()
}

pub fn opt_timestamp(ts: &Option<prost_types::Timestamp>) -> serde_json::Value {
    match ts {
        Some(t) => serde_json::Value::String(timestamp_to_string(t)),
        None => serde_json::Value::Null,
    }
}

pub fn page_to_json(p: &Option<PageResponse>) -> serde_json::Value {
    match p {
        Some(pg) => serde_json::json!({
            "nextPageCursor": pg.next_page_cursor,
            "hasMore": pg.has_more,
            "totalEstimate": pg.total_estimate,
        }),
        None => serde_json::json!(null),
    }
}

pub fn scope_type_name(t: i32) -> &'static str {
    match ScopeType::try_from(t) {
        Ok(ScopeType::Org) => "ORG",
        Ok(ScopeType::Workspace) => "WORKSPACE",
        Ok(ScopeType::Project) => "PROJECT",
        Ok(ScopeType::Agent) => "AGENT",
        _ => "UNSPECIFIED",
    }
}

pub fn labels_to_json(l: &Option<Labels>) -> serde_json::Value {
    match l {
        Some(labels) => serde_json::to_value(&labels.entries).unwrap_or_default(),
        None => serde_json::json!({}),
    }
}

pub fn scope_to_json(s: &Option<ResourceScope>) -> serde_json::Value {
    match s {
        Some(scope) => serde_json::json!({
            "scopeType": scope_type_name(scope.scope_type),
            "scopeId": scope.scope_id,
        }),
        None => serde_json::json!(null),
    }
}

pub fn prost_struct_to_json(s: &Option<prost_types::Struct>) -> serde_json::Value {
    match s {
        Some(st) => {
            let mut map = serde_json::Map::new();
            for (k, v) in &st.fields {
                map.insert(k.clone(), crate::services::policy::prost_value_to_json(v));
            }
            serde_json::Value::Object(map)
        }
        None => serde_json::json!(null),
    }
}

pub fn parse_scope(v: &serde_json::Value) -> Result<ResourceScope, String> {
    let scope_type_str = v
        .get("scopeType")
        .or_else(|| v.get("scope_type"))
        .and_then(|v| v.as_str())
        .unwrap_or("ORG");
    let scope_type = match scope_type_str.to_uppercase().as_str() {
        "ORG" => ScopeType::Org,
        "WORKSPACE" => ScopeType::Workspace,
        "PROJECT" => ScopeType::Project,
        "AGENT" => ScopeType::Agent,
        _ => return Err("invalid scopeType".into()),
    };
    let scope_id = v
        .get("scopeId")
        .or_else(|| v.get("scope_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Ok(ResourceScope {
        scope_type: scope_type as i32,
        scope_id,
    })
}

pub fn parse_page_request(v: &serde_json::Value) -> crate::proto::common_v1::PageRequest {
    crate::proto::common_v1::PageRequest {
        page_size: v
            .get("pageSize")
            .or_else(|| v.get("page_size"))
            .and_then(|v| v.as_i64())
            .unwrap_or(50) as i32,
        page_cursor: v
            .get("pageCursor")
            .or_else(|| v.get("page_cursor"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    }
}

pub fn json_str(v: &serde_json::Value, key: &str) -> String {
    v.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

pub fn json_str_camel(v: &serde_json::Value, camel: &str, snake: &str) -> String {
    v.get(camel)
        .or_else(|| v.get(snake))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

pub fn json_i64(v: &serde_json::Value, key: &str) -> i64 {
    v.get(key).and_then(|v| v.as_i64()).unwrap_or(0)
}

pub fn json_bool(v: &serde_json::Value, camel: &str, snake: &str) -> bool {
    v.get(camel)
        .or_else(|| v.get(snake))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

pub fn json_to_prost_struct(v: &serde_json::Value) -> Option<prost_types::Struct> {
    if v.is_null() {
        return None;
    }
    Some(crate::services::policy::json_to_struct(v))
}
