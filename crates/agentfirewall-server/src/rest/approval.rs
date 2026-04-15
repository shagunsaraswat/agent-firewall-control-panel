use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::{require_permission, AuthContext, Permission};
use crate::proto::approval_v1::{
    Approval, ApprovalStatus, CreateApprovalRequest, GetApprovalRequest, ListApprovalsRequest,
    ResolveApprovalRequest, RevalidateApprovalRequest, WitnessBundle,
};
use crate::proto::ApprovalService;
use crate::proto::common_v1::PageRequest;

use super::bridge::*;
use super::error::{auth_error_response, error_response};
use super::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/approvals", post(create_approval).get(list_approvals))
        .route("/approvals/:approval_id", get(get_approval))
        .route("/approvals/:approval_id/resolve", post(resolve_approval))
        .route(
            "/approvals/:approval_id/revalidate",
            post(revalidate_approval),
        )
}

#[derive(Debug, Deserialize, Default)]
struct ListApprovalsQuery {
    #[serde(default, rename = "scopeType")]
    _scope_type: Option<String>,
    #[serde(default, rename = "scopeId")]
    _scope_id: Option<String>,
    #[serde(default, rename = "runId")]
    run_id: Option<String>,
    #[serde(default, rename = "statusFilter")]
    status_filter: Option<String>,
    #[serde(default, rename = "pageSize")]
    page_size: Option<i32>,
    #[serde(default, rename = "pageCursor")]
    page_cursor: Option<String>,
}

fn approval_status_name(status: i32) -> &'static str {
    match ApprovalStatus::try_from(status).unwrap_or(ApprovalStatus::Unspecified) {
        ApprovalStatus::Pending => "PENDING",
        ApprovalStatus::Approved => "APPROVED",
        ApprovalStatus::Rejected => "REJECTED",
        ApprovalStatus::Expired => "EXPIRED",
        ApprovalStatus::Cancelled => "CANCELLED",
        ApprovalStatus::Unspecified => "UNSPECIFIED",
    }
}

fn ttl_seconds_from_approval(a: &Approval) -> i64 {
    match (a.created_at.as_ref(), a.expires_at.as_ref()) {
        (Some(c), Some(e)) => (e.seconds - c.seconds).max(0),
        _ => 0,
    }
}

fn witness_bundle_to_json(w: &Option<WitnessBundle>) -> serde_json::Value {
    match w {
        None => serde_json::Value::Null,
        Some(w) => {
            let algo = if w.content_hash.len() == 64 {
                "SHA256"
            } else {
                "UNKNOWN"
            };
            serde_json::json!({
                "resourceType": "WITNESS",
                "resourceId": w.cas_uri,
                "hash": w.content_hash,
                "hashAlgorithm": algo,
            })
        }
    }
}

fn resolution_to_json(a: &Approval) -> serde_json::Value {
    let has = !a.resolved_by.is_empty()
        || a.resolved_at.is_some()
        || !a.resolution_comment.is_empty();
    if !has {
        return serde_json::Value::Null;
    }
    serde_json::json!({
        "resolvedBy": a.resolved_by,
        "resolvedAt": opt_timestamp(&a.resolved_at),
        "comment": a.resolution_comment,
    })
}

fn approval_to_json(a: &Approval) -> serde_json::Value {
    let updated_at = a
        .resolved_at
        .as_ref()
        .map(|t| serde_json::Value::String(timestamp_to_string(t)))
        .unwrap_or_else(|| opt_timestamp(&a.created_at));

    serde_json::json!({
        "approvalId": a.approval_id,
        "runId": a.run_id,
        "scope": serde_json::Value::Null,
        "status": approval_status_name(a.status),
        "ttlSeconds": ttl_seconds_from_approval(a),
        "expiresAt": opt_timestamp(&a.expires_at),
        "witness": witness_bundle_to_json(&a.witness),
        "resolution": resolution_to_json(a),
        "createdAt": opt_timestamp(&a.created_at),
        "updatedAt": updated_at,
    })
}

fn parse_witness_bundle(v: &serde_json::Value) -> Result<WitnessBundle, String> {
    let content_hash = json_str_camel(v, "hash", "content_hash");
    let mut cas_uri = json_str_camel(v, "resourceId", "resource_id");
    if cas_uri.is_empty() {
        cas_uri = json_str_camel(v, "casUri", "cas_uri");
    }
    if content_hash.is_empty() {
        return Err("witness.hash (or content_hash) is required".into());
    }
    if cas_uri.is_empty() {
        return Err("witness.resourceId (or cas_uri) is required".into());
    }
    Ok(WitnessBundle {
        content_hash,
        cas_uri,
    })
}

fn parse_status_filter(s: Option<&str>) -> i32 {
    let Some(t) = s.map(str::trim).filter(|x| !x.is_empty()) else {
        return ApprovalStatus::Unspecified as i32;
    };
    match t.to_uppercase().as_str() {
        "PENDING" => ApprovalStatus::Pending as i32,
        "APPROVED" => ApprovalStatus::Approved as i32,
        "REJECTED" => ApprovalStatus::Rejected as i32,
        "EXPIRED" => ApprovalStatus::Expired as i32,
        "CANCELLED" | "ESCALATED" => ApprovalStatus::Cancelled as i32,
        _ => ApprovalStatus::Unspecified as i32,
    }
}

fn parse_resolution_status(s: &str) -> Result<i32, String> {
    match s.to_uppercase().as_str() {
        "APPROVED" => Ok(ApprovalStatus::Approved as i32),
        "REJECTED" => Ok(ApprovalStatus::Rejected as i32),
        "ESCALATED" | "CANCELLED" => Ok(ApprovalStatus::Cancelled as i32),
        _ => Err("resolution must be APPROVED, REJECTED, ESCALATED, or CANCELLED".to_string()),
    }
}

fn bad_request(msg: impl AsRef<str>) -> axum::response::Response {
    error_response(
        StatusCode::BAD_REQUEST,
        "INVALID_ARGUMENT",
        msg.as_ref(),
    )
}

async fn create_approval(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<axum::response::Response, axum::response::Response> {
    require_permission(&ctx, Permission::ApprovalWrite).map_err(auth_error_response)?;

    let idempotency_key = crate::idempotency::extract_key_rest(&headers);

    let run_id = json_str_camel(&body, "runId", "run_id");
    let step_index = body
        .get("stepIndex")
        .or_else(|| body.get("step_index"))
        .and_then(|v| v.as_i64())
        .unwrap_or(0) as i32;
    let policy_id = json_str_camel(&body, "policyId", "policy_id");
    let rule_id = json_str_camel(&body, "ruleId", "rule_id");
    let reason_code = json_str_camel(&body, "reasonCode", "reason_code");
    let requested_by = json_str_camel(&body, "requestedBy", "requested_by");

    let request_payload = body
        .get("requestPayload")
        .or_else(|| body.get("request_payload"))
        .and_then(json_to_prost_struct);

    let witness_val = body
        .get("witness")
        .ok_or_else(|| bad_request("witness is required"))?;
    let witness = parse_witness_bundle(witness_val).map_err(bad_request)?;

    let ttl = if let Some(n) = body
        .get("ttlSeconds")
        .or_else(|| body.get("ttl_seconds"))
        .and_then(|v| v.as_i64())
    {
        format!("{n}s")
    } else {
        json_str_camel(&body, "ttl", "ttl")
    };

    let proto_req = CreateApprovalRequest {
        idempotency: None,
        run_id,
        step_index,
        policy_id,
        rule_id,
        reason_code,
        request_payload,
        witness: Some(witness),
        requested_by,
        ttl,
    };

    let grpc_req = make_grpc_request_with_idempotency(ctx, proto_req, idempotency_key.as_deref());
    let resp = ApprovalService::create_approval(&state.approval_svc, grpc_req)
        .await
        .map_err(status_to_rest_error)?;
    let inner = resp.into_inner();
    let approval = inner
        .approval
        .as_ref()
        .ok_or_else(|| error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "missing approval in response",
        ))?;

    Ok(created_json(serde_json::json!({
        "approval": approval_to_json(approval),
    })))
}

async fn list_approvals(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<AppState>,
    Query(q): Query<ListApprovalsQuery>,
) -> Result<axum::response::Response, axum::response::Response> {
    require_permission(&ctx, Permission::ApprovalRead).map_err(auth_error_response)?;

    let page = PageRequest {
        page_size: q.page_size.unwrap_or(50),
        page_cursor: q.page_cursor.clone().unwrap_or_default(),
    };

    let proto_req = ListApprovalsRequest {
        page: Some(page),
        run_id: q.run_id.clone().unwrap_or_default(),
        status_filter: parse_status_filter(q.status_filter.as_deref()),
    };

    let grpc_req = make_grpc_request(ctx, proto_req);
    let resp = ApprovalService::list_approvals(&state.approval_svc, grpc_req)
        .await
        .map_err(status_to_rest_error)?;
    let inner = resp.into_inner();

    let approvals: Vec<serde_json::Value> = inner.approvals.iter().map(approval_to_json).collect();

    Ok(ok_json(serde_json::json!({
        "approvals": approvals,
        "page": page_to_json(&inner.page),
    })))
}

async fn get_approval(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(approval_id): Path<Uuid>,
) -> Result<axum::response::Response, axum::response::Response> {
    require_permission(&ctx, Permission::ApprovalRead).map_err(auth_error_response)?;

    let proto_req = GetApprovalRequest {
        approval_id: approval_id.to_string(),
    };

    let grpc_req = make_grpc_request(ctx, proto_req);
    let resp = ApprovalService::get_approval(&state.approval_svc, grpc_req)
        .await
        .map_err(status_to_rest_error)?;
    let inner = resp.into_inner();
    let approval = inner
        .approval
        .as_ref()
        .ok_or_else(|| error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "missing approval in response",
        ))?;

    Ok(ok_json(serde_json::json!({
        "approval": approval_to_json(approval),
    })))
}

async fn resolve_approval(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(approval_id): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> Result<axum::response::Response, axum::response::Response> {
    require_permission(&ctx, Permission::ApprovalWrite).map_err(auth_error_response)?;

    let resolution_str = json_str_camel(&body, "resolution", "resolution");
    if resolution_str.is_empty() {
        return Err(bad_request("resolution is required"));
    }
    let resolution = parse_resolution_status(&resolution_str).map_err(bad_request)?;

    let resolved_by = json_str_camel(&body, "resolvedBy", "resolved_by");
    let resolution_comment = body
        .get("comment")
        .or_else(|| body.get("resolutionComment"))
        .or_else(|| body.get("resolution_comment"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let proto_req = ResolveApprovalRequest {
        idempotency: None,
        approval_id: approval_id.to_string(),
        resolution,
        resolved_by,
        resolution_comment,
    };

    let grpc_req = make_grpc_request(ctx, proto_req);
    let resp = ApprovalService::resolve_approval(&state.approval_svc, grpc_req)
        .await
        .map_err(status_to_rest_error)?;
    let inner = resp.into_inner();
    let approval = inner
        .approval
        .as_ref()
        .ok_or_else(|| error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "missing approval in response",
        ))?;

    Ok(ok_json(serde_json::json!({
        "approval": approval_to_json(approval),
    })))
}

async fn revalidate_approval(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(approval_id): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> Result<axum::response::Response, axum::response::Response> {
    require_permission(&ctx, Permission::ApprovalRead).map_err(auth_error_response)?;

    let witness_val = body
        .get("witness")
        .ok_or_else(|| bad_request("witness is required"))?;
    let witness = parse_witness_bundle(witness_val).map_err(bad_request)?;

    let revalidation_context = body
        .get("revalidationContext")
        .or_else(|| body.get("revalidation_context"))
        .and_then(json_to_prost_struct);

    let proto_req = RevalidateApprovalRequest {
        idempotency: None,
        approval_id: approval_id.to_string(),
        witness: Some(witness),
        revalidation_context,
    };

    let grpc_req = make_grpc_request(ctx, proto_req);
    let resp = ApprovalService::revalidate_approval(&state.approval_svc, grpc_req)
        .await
        .map_err(status_to_rest_error)?;
    let inner = resp.into_inner();
    let approval = inner
        .approval
        .as_ref()
        .ok_or_else(|| error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "missing approval in response",
        ))?;

    Ok(ok_json(serde_json::json!({
        "approval": approval_to_json(approval),
        "witnessValid": inner.witness_valid,
        "reasonCode": inner.reason_code,
    })))
}
