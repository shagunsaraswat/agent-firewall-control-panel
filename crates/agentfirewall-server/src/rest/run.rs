use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::{require_permission, AuthContext, Permission};
use crate::proto::common_v1::{Labels, PageRequest, ResourceScope, ScopeType};
use crate::proto::run_v1::{
    BudgetComponent, BudgetState, BudgetUnit, CancelRunRequest, CompleteRunRequest,
    CostAttribution, CreateRunRequest, GetRunRequest, ListRunsRequest, Run, RunStatus,
};
use crate::proto::RunService;

use super::bridge::*;
use super::error::{auth_error_response, error_response};
use super::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/runs", post(create_run).get(list_runs))
        .route("/runs/:run_id", get(get_run))
        .route("/runs/:run_id/complete", post(complete_run))
        .route("/runs/:run_id/cancel", post(cancel_run))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateRunBody {
    scope: serde_json::Value,
    agent_id: String,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    initial_budget: Option<serde_json::Value>,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
    #[serde(default)]
    labels: Option<serde_json::Value>,
    #[serde(default)]
    goal: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListRunsQuery {
    #[serde(default)]
    scope_type: Option<String>,
    #[serde(default)]
    scope_id: Option<String>,
    #[serde(default)]
    status_filter: Option<String>,
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default)]
    page_size: Option<i32>,
    #[serde(default)]
    page_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CompleteRunBody {
    terminal_status: String,
    #[serde(default)]
    outcome: Option<serde_json::Value>,
    #[serde(default)]
    final_attribution: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CancelRunBody {
    #[serde(default)]
    reason_code: String,
    #[serde(default)]
    comment: String,
}

async fn create_run(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateRunBody>,
) -> Result<axum::response::Response, axum::response::Response> {
    require_permission(&ctx, Permission::RunWrite).map_err(auth_error_response)?;

    let idempotency_key = crate::idempotency::extract_key_rest(&headers);

    let scope = parse_scope(&body.scope).map_err(|e| {
        error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            &format!("scope: {e}"),
        )
    })?;

    let initial_budget = match body.initial_budget.as_ref() {
        Some(v) if !v.is_null() => Some(parse_budget_state_from_json(v).map_err(|e| {
            error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_ARGUMENT",
                &format!("initialBudget: {e}"),
            )
        })?),
        _ => None,
    };

    let labels = parse_labels_value(body.labels.as_ref());
    let metadata = body
        .metadata
        .as_ref()
        .and_then(json_to_prost_struct);

    let proto_req = CreateRunRequest {
        idempotency: None,
        scope: Some(scope),
        agent_id: body.agent_id,
        initial_budget,
        labels,
        metadata,
        mode: body.mode,
        goal: body.goal,
    };

    let grpc_req = make_grpc_request_with_idempotency(ctx, proto_req, idempotency_key.as_deref());
    let resp = RunService::create_run(&state.run_svc, grpc_req)
        .await
        .map_err(status_to_rest_error)?;
    let run = resp
        .into_inner()
        .run
        .ok_or_else(|| status_to_rest_error(tonic::Status::internal("missing run")))?;

    Ok(created_json(run_to_json(&run)))
}

async fn list_runs(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<AppState>,
    Query(q): Query<ListRunsQuery>,
) -> Result<axum::response::Response, axum::response::Response> {
    require_permission(&ctx, Permission::RunRead).map_err(auth_error_response)?;

    let scope_type_str = q.scope_type.as_deref().unwrap_or("").trim();
    let scope_id_str = q.scope_id.as_deref().unwrap_or("").trim();
    if scope_type_str.is_empty() || scope_id_str.is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            "scopeType and scopeId are required",
        ));
    }

    let scope_type = parse_scope_type_str(scope_type_str).map_err(|msg| {
        error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            &msg,
        )
    })?;

    let scope = ResourceScope {
        scope_type,
        scope_id: scope_id_str.to_string(),
    };

    let status_filter = match q.status_filter.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => parse_run_status_filter(s).map_err(|msg| {
            error_response(StatusCode::BAD_REQUEST, "INVALID_ARGUMENT", &msg)
        })?,
        None => RunStatus::Unspecified as i32,
    };

    let page = PageRequest {
        page_size: q.page_size.unwrap_or(0),
        page_cursor: q.page_cursor.unwrap_or_default(),
    };

    let proto_req = ListRunsRequest {
        page: Some(page),
        scope: Some(scope),
        status_filter,
        agent_id: q.agent_id.unwrap_or_default(),
    };

    let grpc_req = make_grpc_request(ctx, proto_req);
    let resp = RunService::list_runs(&state.run_svc, grpc_req)
        .await
        .map_err(status_to_rest_error)?;
    let inner = resp.into_inner();
    let runs: Vec<serde_json::Value> = inner.runs.iter().map(run_to_json).collect();

    Ok(ok_json(serde_json::json!({
        "runs": runs,
        "page": page_to_json(&inner.page),
    })))
}

async fn get_run(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(run_id): Path<Uuid>,
) -> Result<axum::response::Response, axum::response::Response> {
    require_permission(&ctx, Permission::RunRead).map_err(auth_error_response)?;

    let proto_req = GetRunRequest {
        run_id: run_id.to_string(),
    };

    let grpc_req = make_grpc_request(ctx, proto_req);
    let resp = RunService::get_run(&state.run_svc, grpc_req)
        .await
        .map_err(status_to_rest_error)?;
    let run = resp
        .into_inner()
        .run
        .ok_or_else(|| status_to_rest_error(tonic::Status::internal("missing run")))?;

    Ok(ok_json(run_to_json(&run)))
}

async fn complete_run(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(run_id): Path<Uuid>,
    Json(body): Json<CompleteRunBody>,
) -> Result<axum::response::Response, axum::response::Response> {
    require_permission(&ctx, Permission::RunWrite).map_err(auth_error_response)?;

    let terminal_status = parse_terminal_status(&body.terminal_status).map_err(|msg| {
        error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            &msg,
        )
    })?;

    let outcome = body
        .outcome
        .as_ref()
        .and_then(json_to_prost_struct);

    let final_attribution = match body.final_attribution.as_ref() {
        Some(v) if !v.is_null() => Some(parse_cost_attribution_from_json(v).map_err(|msg| {
            error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_ARGUMENT",
                &format!("finalAttribution: {msg}"),
            )
        })?),
        _ => None,
    };

    let proto_req = CompleteRunRequest {
        idempotency: None,
        run_id: run_id.to_string(),
        terminal_status,
        outcome,
        final_attribution,
    };

    let grpc_req = make_grpc_request(ctx, proto_req);
    let resp = RunService::complete_run(&state.run_svc, grpc_req)
        .await
        .map_err(status_to_rest_error)?;
    let run = resp
        .into_inner()
        .run
        .ok_or_else(|| status_to_rest_error(tonic::Status::internal("missing run")))?;

    Ok(ok_json(run_to_json(&run)))
}

async fn cancel_run(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(run_id): Path<Uuid>,
    Json(body): Json<CancelRunBody>,
) -> Result<axum::response::Response, axum::response::Response> {
    require_permission(&ctx, Permission::RunWrite).map_err(auth_error_response)?;

    let proto_req = CancelRunRequest {
        idempotency: None,
        run_id: run_id.to_string(),
        reason_code: body.reason_code,
        comment: body.comment,
    };

    let grpc_req = make_grpc_request(ctx, proto_req);
    let resp = RunService::cancel_run(&state.run_svc, grpc_req)
        .await
        .map_err(status_to_rest_error)?;
    let run = resp
        .into_inner()
        .run
        .ok_or_else(|| status_to_rest_error(tonic::Status::internal("missing run")))?;

    Ok(ok_json(run_to_json(&run)))
}

fn run_status_name(s: i32) -> &'static str {
    match RunStatus::try_from(s) {
        Ok(RunStatus::Pending) => "PENDING",
        Ok(RunStatus::Running) => "RUNNING",
        Ok(RunStatus::Completed) => "COMPLETED",
        Ok(RunStatus::Failed) => "FAILED",
        Ok(RunStatus::Cancelled) => "CANCELLED",
        Ok(RunStatus::Blocked) => "BLOCKED",
        _ => "UNSPECIFIED",
    }
}

fn budget_unit_name(u: i32) -> &'static str {
    match BudgetUnit::try_from(u) {
        Ok(BudgetUnit::Usd) => "USD",
        Ok(BudgetUnit::Tokens) => "TOKENS",
        Ok(BudgetUnit::Requests) => "STEPS",
        _ => "UNSPECIFIED",
    }
}

fn budget_state_to_json(b: &BudgetState) -> serde_json::Value {
    let components: Vec<serde_json::Value> = b
        .components
        .iter()
        .map(|c| {
            serde_json::json!({
                "unit": budget_unit_name(c.unit),
                "reserved": c.reserved,
                "consumed": c.consumed,
                "limit": c.limit,
            })
        })
        .collect();
    serde_json::json!({
        "components": components,
        "updatedAt": opt_timestamp(&b.updated_at),
    })
}

fn cost_attribution_to_json(a: &CostAttribution) -> serde_json::Value {
    serde_json::json!({
        "model": a.model,
        "tool": a.tool,
        "estimatedUsd": a.estimated_usd,
        "actualUsd": a.actual_usd,
        "promptTokens": a.prompt_tokens,
        "completionTokens": a.completion_tokens,
    })
}

fn run_to_json(r: &Run) -> serde_json::Value {
    let budget = match &r.budget {
        Some(b) => budget_state_to_json(b),
        None => serde_json::Value::Null,
    };
    let last_attribution = match &r.last_attribution {
        Some(a) => cost_attribution_to_json(a),
        None => serde_json::Value::Null,
    };
    serde_json::json!({
        "runId": r.run_id,
        "scope": scope_to_json(&r.scope),
        "agentId": r.agent_id,
        "status": run_status_name(r.status),
        "stepIndex": r.step_index,
        "startedAt": opt_timestamp(&r.started_at),
        "endedAt": opt_timestamp(&r.ended_at),
        "budget": budget,
        "lastAttribution": last_attribution,
        "labels": labels_to_json(&r.labels),
        "metadata": prost_struct_to_json(&r.metadata),
        "mode": r.mode,
        "goal": r.goal,
    })
}

fn parse_labels_value(v: Option<&serde_json::Value>) -> Option<Labels> {
    let v = v?;
    let obj = v.as_object()?;
    let entries = obj
        .iter()
        .filter_map(|(k, val)| val.as_str().map(|s| (k.clone(), s.to_string())))
        .collect();
    Some(Labels { entries })
}

fn parse_budget_unit_field(v: Option<&serde_json::Value>) -> Result<i32, String> {
    let v = v.ok_or_else(|| "component.unit is required".to_string())?;
    match v {
        serde_json::Value::Number(n) => n
            .as_i64()
            .map(|x| x as i32)
            .ok_or_else(|| "invalid unit number".to_string()),
        serde_json::Value::String(s) => parse_budget_unit_str(s),
        _ => Err("unit must be a string or number".to_string()),
    }
}

fn parse_budget_unit_str(s: &str) -> Result<i32, String> {
    match s.trim().to_uppercase().as_str() {
        "USD" => Ok(BudgetUnit::Usd as i32),
        "TOKENS" => Ok(BudgetUnit::Tokens as i32),
        "REQUESTS" | "STEPS" => Ok(BudgetUnit::Requests as i32),
        _ => Err(format!("unknown budget unit: {s}")),
    }
}

fn parse_budget_state_from_json(v: &serde_json::Value) -> Result<BudgetState, String> {
    let obj = v
        .as_object()
        .ok_or_else(|| "initialBudget must be an object".to_string())?;
    let arr = obj
        .get("components")
        .and_then(|c| c.as_array())
        .ok_or_else(|| "initialBudget.components must be an array".to_string())?;
    let mut components = Vec::new();
    for item in arr {
        let unit = parse_budget_unit_field(item.get("unit"))?;
        let reserved = item.get("reserved").and_then(|x| x.as_f64()).unwrap_or(0.0);
        let consumed = item.get("consumed").and_then(|x| x.as_f64()).unwrap_or(0.0);
        let limit = item.get("limit").and_then(|x| x.as_f64()).unwrap_or(0.0);
        components.push(BudgetComponent {
            unit,
            reserved,
            consumed,
            limit,
        });
    }
    let updated_at = obj
        .get("updatedAt")
        .or_else(|| obj.get("updated_at"))
        .and_then(|t| t.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| prost_types::Timestamp {
            seconds: dt.timestamp(),
            nanos: dt.timestamp_subsec_nanos() as i32,
        });
    Ok(BudgetState {
        components,
        updated_at,
    })
}

fn parse_cost_attribution_from_json(v: &serde_json::Value) -> Result<CostAttribution, String> {
    let o = v
        .as_object()
        .ok_or_else(|| "must be an object".to_string())?;
    Ok(CostAttribution {
        model: o
            .get("model")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        tool: o
            .get("tool")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        estimated_usd: o
            .get("estimatedUsd")
            .or_else(|| o.get("estimated_usd"))
            .and_then(|x| x.as_f64())
            .unwrap_or(0.0),
        actual_usd: o
            .get("actualUsd")
            .or_else(|| o.get("actual_usd"))
            .and_then(|x| x.as_f64())
            .unwrap_or(0.0),
        prompt_tokens: o
            .get("promptTokens")
            .or_else(|| o.get("prompt_tokens"))
            .and_then(|x| x.as_i64())
            .unwrap_or(0),
        completion_tokens: o
            .get("completionTokens")
            .or_else(|| o.get("completion_tokens"))
            .and_then(|x| x.as_i64())
            .unwrap_or(0),
    })
}

fn parse_scope_type_str(s: &str) -> Result<i32, String> {
    let st = match s.to_uppercase().as_str() {
        "ORG" => ScopeType::Org,
        "WORKSPACE" => ScopeType::Workspace,
        "PROJECT" => ScopeType::Project,
        "AGENT" => ScopeType::Agent,
        _ => return Err(format!("invalid scopeType: {s}")),
    };
    Ok(st as i32)
}

fn parse_run_status_filter(s: &str) -> Result<i32, String> {
    match s.to_uppercase().as_str() {
        "PENDING" => Ok(RunStatus::Pending as i32),
        "RUNNING" => Ok(RunStatus::Running as i32),
        "COMPLETED" => Ok(RunStatus::Completed as i32),
        "FAILED" => Ok(RunStatus::Failed as i32),
        "CANCELLED" | "CANCELED" => Ok(RunStatus::Cancelled as i32),
        "BLOCKED" => Ok(RunStatus::Blocked as i32),
        _ => Err(format!("invalid statusFilter: {s}")),
    }
}

fn parse_terminal_status(s: &str) -> Result<i32, String> {
    match s.trim().to_uppercase().as_str() {
        "COMPLETED" => Ok(RunStatus::Completed as i32),
        "FAILED" => Ok(RunStatus::Failed as i32),
        _ => Err("terminalStatus must be COMPLETED or FAILED".to_string()),
    }
}
