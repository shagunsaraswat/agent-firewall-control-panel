use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::{require_permission, AuthContext, Permission};
use crate::proto::common_v1::{PageRequest, ResourceScope, ScopeType};
use crate::proto::incident_v1::{
    AcknowledgeIncidentRequest, CreateIncidentRequest, GetIncidentRequest, Incident,
    IncidentSeverity, IncidentStatus, ListIncidentsRequest, RemediationStep,
    ResolveIncidentRequest,
};
use crate::proto::IncidentService;

use super::bridge::*;
use super::error::{auth_error_response, error_response};
use super::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/incidents", post(create_incident).get(list_incidents))
        .route("/incidents/:incident_id", get(get_incident))
        .route(
            "/incidents/:incident_id/acknowledge",
            post(acknowledge_incident),
        )
        .route("/incidents/:incident_id/resolve", post(resolve_incident))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListIncidentsQuery {
    scope_type: Option<String>,
    scope_id: Option<String>,
    status_filter: Option<String>,
    severity_at_least: Option<String>,
    reason_code_prefix: Option<String>,
    page_size: Option<i32>,
    page_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcknowledgeIncidentBody {
    acknowledged_by: String,
    #[serde(default)]
    comment: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResolveIncidentBody {
    summary: String,
    resolution_metadata: Option<ResolveMetadataBody>,
    #[serde(default)]
    resolved_by: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResolveMetadataBody {
    #[serde(default)]
    dismissed: bool,
}

fn incident_severity_label(v: i32) -> &'static str {
    match IncidentSeverity::try_from(v) {
        Ok(IncidentSeverity::Info) => "INFO",
        Ok(IncidentSeverity::Low) => "LOW",
        Ok(IncidentSeverity::Medium) => "MEDIUM",
        Ok(IncidentSeverity::High) => "HIGH",
        Ok(IncidentSeverity::Critical) => "CRITICAL",
        _ => "UNSPECIFIED",
    }
}

fn incident_status_label(v: i32) -> &'static str {
    match IncidentStatus::try_from(v) {
        Ok(IncidentStatus::Open) => "OPEN",
        Ok(IncidentStatus::Acknowledged) => "ACKNOWLEDGED",
        Ok(IncidentStatus::Resolved) => "RESOLVED",
        Ok(IncidentStatus::Dismissed) => "DISMISSED",
        _ => "UNSPECIFIED",
    }
}

fn parse_incident_severity(s: &str) -> IncidentSeverity {
    match s.trim().to_uppercase().as_str() {
        "INFO" => IncidentSeverity::Info,
        "LOW" => IncidentSeverity::Low,
        "MEDIUM" => IncidentSeverity::Medium,
        "HIGH" => IncidentSeverity::High,
        "CRITICAL" => IncidentSeverity::Critical,
        _ => IncidentSeverity::Unspecified,
    }
}

fn parse_incident_status(s: &str) -> IncidentStatus {
    match s.trim().to_uppercase().as_str() {
        "OPEN" => IncidentStatus::Open,
        "ACKNOWLEDGED" => IncidentStatus::Acknowledged,
        "RESOLVED" => IncidentStatus::Resolved,
        "DISMISSED" => IncidentStatus::Dismissed,
        _ => IncidentStatus::Unspecified,
    }
}

/// REST shape aligned with proto-backed fields; timestamps only where the proto exposes them.
fn incident_to_json(inc: &Incident) -> serde_json::Value {
    let first = inc.remediation.first();
    serde_json::json!({
        "incidentId": inc.incident_id,
        "runId": inc.run_id,
        "approvalId": inc.approval_id,
        "scope": scope_to_json(&inc.scope),
        "severity": incident_severity_label(inc.severity),
        "status": incident_status_label(inc.status),
        "reasonCode": inc.reason_code,
        "title": inc.title,
        "summary": inc.summary,
        "detail": prost_struct_to_json(&inc.context),
        "remediation": {
            "type": first.map(|s| s.title.as_str()).unwrap_or(""),
            "description": first.map(|s| s.description.as_str()).unwrap_or(""),
        },
        "policyId": inc.policy_id,
        "createdBy": inc.created_by,
        "owner": inc.owner,
        "acknowledgedBy": "",
        "acknowledgedAt": serde_json::Value::Null,
        "resolvedAt": serde_json::Value::Null,
        "occurredAt": opt_timestamp(&inc.created_at),
        "createdAt": opt_timestamp(&inc.created_at),
        "updatedAt": opt_timestamp(&inc.updated_at),
    })
}

fn parse_remediation_from_json(v: &serde_json::Value) -> Vec<RemediationStep> {
    if let Some(arr) = v.as_array() {
        return arr
            .iter()
            .map(|e| {
                let step_id = json_str_camel(e, "stepId", "step_id");
                let title = json_str_camel(e, "title", "title");
                let description = json_str_camel(e, "description", "description");
                let completed = json_bool(e, "completed", "completed");
                let completed_by = json_str_camel(e, "completedBy", "completed_by");
                RemediationStep {
                    step_id,
                    title,
                    description,
                    completed,
                    completed_at: None,
                    completed_by,
                }
            })
            .collect();
    }
    if let Some(obj) = v.as_object() {
        let typ = obj
            .get("type")
            .or_else(|| obj.get("title"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let description = obj
            .get("description")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if !typ.is_empty() || !description.is_empty() {
            return vec![RemediationStep {
                step_id: String::new(),
                title: typ,
                description,
                completed: false,
                completed_at: None,
                completed_by: String::new(),
            }];
        }
    }
    vec![]
}

async fn create_incident(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<axum::response::Response, axum::response::Response> {
    require_permission(&ctx, Permission::IncidentWrite).map_err(auth_error_response)?;

    let idempotency_key = crate::idempotency::extract_key_rest(&headers);

    let scope = match body.get("scope") {
        None => None,
        Some(v) if v.is_null() => None,
        Some(v) => Some(parse_scope(v).map_err(|msg| {
            error_response(StatusCode::BAD_REQUEST, "INVALID_ARGUMENT", &msg)
        })?),
    };

    let severity = parse_incident_severity(&json_str_camel(
        &body,
        "severity",
        "severity",
    ));
    if severity == IncidentSeverity::Unspecified {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            "severity is required (INFO, LOW, MEDIUM, HIGH, CRITICAL)",
        ));
    }

    let reason_code = json_str_camel(&body, "reasonCode", "reason_code");
    if reason_code.trim().is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            "reasonCode is required",
        ));
    }

    let remediation = body
        .get("remediation")
        .map(parse_remediation_from_json)
        .unwrap_or_default();

    let context = body
        .get("detail")
        .or_else(|| body.get("context"))
        .and_then(json_to_prost_struct);

    let proto_req = CreateIncidentRequest {
        idempotency: None,
        severity: severity.into(),
        title: json_str_camel(&body, "title", "title"),
        summary: json_str_camel(&body, "summary", "summary"),
        reason_code,
        run_id: json_str_camel(&body, "runId", "run_id"),
        policy_id: json_str_camel(&body, "policyId", "policy_id"),
        approval_id: json_str_camel(&body, "approvalId", "approval_id"),
        scope,
        context,
        remediation,
        created_by: {
            let from_body = json_str_camel(&body, "createdBy", "created_by");
            if from_body.trim().is_empty() {
                ctx.principal_id.clone()
            } else {
                from_body
            }
        },
    };

    let grpc_req = make_grpc_request_with_idempotency(ctx, proto_req, idempotency_key.as_deref());
    let resp = state
        .incident_svc
        .create_incident(grpc_req)
        .await
        .map_err(status_to_rest_error)?;
    let inc = resp
        .into_inner()
        .incident
        .ok_or_else(|| status_to_rest_error(tonic::Status::internal("missing incident")))?;

    Ok(created_json(incident_to_json(&inc)))
}

async fn list_incidents(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<AppState>,
    Query(q): Query<ListIncidentsQuery>,
) -> Result<axum::response::Response, axum::response::Response> {
    require_permission(&ctx, Permission::IncidentRead).map_err(auth_error_response)?;

    let scope = match (&q.scope_type, &q.scope_id) {
        (Some(st), Some(sid)) => {
            let st = st.trim().to_uppercase();
            let scope_type = match st.as_str() {
                "ORG" => ScopeType::Org,
                "WORKSPACE" => ScopeType::Workspace,
                "PROJECT" => ScopeType::Project,
                "AGENT" => ScopeType::Agent,
                _ => {
                    return Err(error_response(
                        StatusCode::BAD_REQUEST,
                        "INVALID_ARGUMENT",
                        "invalid scopeType",
                    ));
                }
            };
            if sid.trim().is_empty() {
                return Err(error_response(
                    StatusCode::BAD_REQUEST,
                    "INVALID_ARGUMENT",
                    "scopeId is required when scopeType is set",
                ));
            }
            Some(ResourceScope {
                scope_type: scope_type.into(),
                scope_id: sid.clone(),
            })
        }
        (None, None) => None,
        _ => {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_ARGUMENT",
                "scope requires both scopeType and scopeId",
            ));
        }
    };

    let status_filter = q
        .status_filter
        .as_deref()
        .map(parse_incident_status)
        .unwrap_or(IncidentStatus::Unspecified);

    let severity_at_least = q
        .severity_at_least
        .as_deref()
        .map(parse_incident_severity)
        .unwrap_or(IncidentSeverity::Unspecified);

    let proto_req = ListIncidentsRequest {
        page: Some(PageRequest {
            page_size: q.page_size.unwrap_or(50),
            page_cursor: q.page_cursor.clone().unwrap_or_default(),
        }),
        scope,
        status_filter: status_filter.into(),
        severity_at_least: severity_at_least.into(),
        reason_code_prefix: q.reason_code_prefix.clone().unwrap_or_default(),
    };

    let grpc_req = make_grpc_request(ctx, proto_req);
    let resp = state
        .incident_svc
        .list_incidents(grpc_req)
        .await
        .map_err(status_to_rest_error)?;
    let inner = resp.into_inner();
    let incidents: Vec<serde_json::Value> =
        inner.incidents.iter().map(incident_to_json).collect();

    Ok(ok_json(serde_json::json!({
        "incidents": incidents,
        "page": page_to_json(&inner.page),
    })))
}

async fn get_incident(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(incident_id): Path<Uuid>,
) -> Result<axum::response::Response, axum::response::Response> {
    require_permission(&ctx, Permission::IncidentRead).map_err(auth_error_response)?;

    let proto_req = GetIncidentRequest {
        incident_id: incident_id.to_string(),
    };
    let grpc_req = make_grpc_request(ctx, proto_req);
    let resp = state
        .incident_svc
        .get_incident(grpc_req)
        .await
        .map_err(status_to_rest_error)?;
    let inc = resp
        .into_inner()
        .incident
        .ok_or_else(|| status_to_rest_error(tonic::Status::internal("missing incident")))?;

    Ok(ok_json(incident_to_json(&inc)))
}

async fn acknowledge_incident(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(incident_id): Path<Uuid>,
    Json(body): Json<AcknowledgeIncidentBody>,
) -> Result<axum::response::Response, axum::response::Response> {
    require_permission(&ctx, Permission::IncidentWrite).map_err(auth_error_response)?;

    if body.acknowledged_by.trim().is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            "acknowledgedBy is required",
        ));
    }

    let proto_req = AcknowledgeIncidentRequest {
        idempotency: None,
        incident_id: incident_id.to_string(),
        acknowledged_by: body.acknowledged_by,
        comment: body.comment,
    };

    let grpc_req = make_grpc_request(ctx, proto_req);
    let resp = state
        .incident_svc
        .acknowledge_incident(grpc_req)
        .await
        .map_err(status_to_rest_error)?;
    let inc = resp
        .into_inner()
        .incident
        .ok_or_else(|| status_to_rest_error(tonic::Status::internal("missing incident")))?;

    Ok(ok_json(incident_to_json(&inc)))
}

async fn resolve_incident(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(incident_id): Path<Uuid>,
    Json(body): Json<ResolveIncidentBody>,
) -> Result<axum::response::Response, axum::response::Response> {
    require_permission(&ctx, Permission::IncidentWrite).map_err(auth_error_response)?;

    if body.summary.trim().is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            "summary is required (resolution note)",
        ));
    }

    let dismissed = body.resolution_metadata.as_ref().map(|m| m.dismissed).unwrap_or(false);
    let resolution_metadata = json_to_prost_struct(&serde_json::json!({ "dismissed": dismissed }));

    let proto_req = ResolveIncidentRequest {
        idempotency: None,
        incident_id: incident_id.to_string(),
        resolved_by: body.resolved_by,
        resolution_summary: body.summary,
        resolution_metadata,
    };

    let grpc_req = make_grpc_request(ctx, proto_req);
    let resp = state
        .incident_svc
        .resolve_incident(grpc_req)
        .await
        .map_err(status_to_rest_error)?;
    let inc = resp
        .into_inner()
        .incident
        .ok_or_else(|| status_to_rest_error(tonic::Status::internal("missing incident")))?;

    Ok(ok_json(incident_to_json(&inc)))
}
