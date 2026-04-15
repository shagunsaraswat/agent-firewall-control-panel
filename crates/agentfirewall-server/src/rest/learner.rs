//! REST handlers for `LearnerService`; each route delegates to [`crate::proto::LearnerService`].

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::{require_permission, AuthContext, Permission};
use crate::proto::common_v1::{PageRequest, ResourceScope, ScopeType};
use crate::proto::learner_v1::{
    ApproveCandidateRequest, ApproveCandidateResponse, Baseline, BaselineSignal, CandidateStatus,
    GenerateNowRequest, GenerateNowResponse, GetBaselineRequest, GetBaselineResponse,
    GetCandidateRequest, GetCandidateResponse, GetModeRequest, GetModeResponse,
    LearnerMode as LearnerModeProto, ListCandidatesRequest, ListCandidatesResponse,
    PolicyCandidate, RejectCandidateRequest, RejectCandidateResponse, SetModeRequest,
    SetModeResponse,
};
use crate::proto::policy_v1::{PolicyRule, RuleAction, RuleTargetType};
use crate::proto::LearnerService;

use super::bridge::*;
use super::error::{auth_error_response, error_response};
use super::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().nest(
        "/learner",
        Router::new()
            .route("/mode", get(get_learner_mode).put(put_learner_mode))
            .route("/baseline", get(get_learner_baseline))
            .route("/candidates", get(list_learner_candidates))
            .route("/candidates/:candidate_id", get(get_learner_candidate))
            .route(
                "/candidates/:candidate_id/approve",
                post(approve_learner_candidate),
            )
            .route(
                "/candidates/:candidate_id/reject",
                post(reject_learner_candidate),
            )
            .route("/generate", post(generate_learner)),
    )
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScopeQuery {
    scope_type: String,
    scope_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListCandidatesQuery {
    scope_type: String,
    scope_id: String,
    #[serde(default)]
    status_filter: Option<String>,
    #[serde(default)]
    page_size: Option<i32>,
    #[serde(default)]
    page_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetModeBody {
    scope: serde_json::Value,
    mode: String,
    #[serde(default)]
    comment: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApproveBody {
    #[serde(default)]
    comment: String,
    #[serde(default)]
    activate_as_draft: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RejectBody {
    #[serde(default)]
    comment: String,
    #[serde(default)]
    reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GenerateBody {
    scope: serde_json::Value,
    #[serde(default)]
    generation_hints: Option<serde_json::Value>,
}

fn scope_from_query(q: &ScopeQuery) -> Result<ResourceScope, String> {
    let st = match q.scope_type.trim().to_uppercase().as_str() {
        "ORG" => ScopeType::Org,
        "WORKSPACE" => ScopeType::Workspace,
        "PROJECT" => ScopeType::Project,
        "AGENT" => ScopeType::Agent,
        _ => return Err(format!("invalid scopeType: {}", q.scope_type)),
    };
    Ok(ResourceScope {
        scope_type: st as i32,
        scope_id: q.scope_id.trim().to_string(),
    })
}

fn parse_learner_mode(s: &str) -> Result<i32, String> {
    let u = s.trim().to_uppercase().replace('-', "_");
    let mode = match u.as_str() {
        "MONITOR" | "OBSERVE_ONLY" | "PASSIVE" => LearnerModeProto::ObserveOnly,
        "ENFORCE" | "RECOMMEND" => LearnerModeProto::Recommend,
        "AUTO_PROMOTE_SAFE" => LearnerModeProto::AutoPromoteSafe,
        _ => return Err(format!("invalid mode: {s}")),
    };
    Ok(mode as i32)
}

fn learner_mode_to_json(m: i32) -> &'static str {
    match LearnerModeProto::try_from(m) {
        Ok(LearnerModeProto::ObserveOnly) => "MONITOR",
        Ok(LearnerModeProto::Recommend) => "ENFORCE",
        Ok(LearnerModeProto::AutoPromoteSafe) => "AUTO_PROMOTE_SAFE",
        _ => "UNSPECIFIED",
    }
}

fn parse_candidate_status_filter(s: &str) -> Result<i32, String> {
    match s.trim().to_uppercase().as_str() {
        "PROPOSED" => Ok(CandidateStatus::Proposed as i32),
        "APPROVED" => Ok(CandidateStatus::Approved as i32),
        "REJECTED" => Ok(CandidateStatus::Rejected as i32),
        "SUPERSEDED" => Ok(CandidateStatus::Superseded as i32),
        "UNSPECIFIED" | "" => Ok(CandidateStatus::Unspecified as i32),
        _ => Err(format!("invalid statusFilter: {s}")),
    }
}

fn candidate_status_name(s: i32) -> &'static str {
    match CandidateStatus::try_from(s) {
        Ok(CandidateStatus::Proposed) => "PROPOSED",
        Ok(CandidateStatus::Approved) => "APPROVED",
        Ok(CandidateStatus::Rejected) => "REJECTED",
        Ok(CandidateStatus::Superseded) => "SUPERSEDED",
        _ => "UNSPECIFIED",
    }
}

fn rule_target_type_name(t: i32) -> &'static str {
    match RuleTargetType::try_from(t) {
        Ok(RuleTargetType::Model) => "MODEL",
        Ok(RuleTargetType::Tool) => "TOOL",
        Ok(RuleTargetType::WriteAction) => "WRITE_ACTION",
        Ok(RuleTargetType::Delegation) => "DELEGATION",
        Ok(RuleTargetType::Budget) => "BUDGET",
        _ => "UNSPECIFIED",
    }
}

fn rule_action_name(a: i32) -> &'static str {
    match RuleAction::try_from(a) {
        Ok(RuleAction::Allow) => "ALLOW",
        Ok(RuleAction::Deny) => "DENY",
        Ok(RuleAction::RequireApproval) => "REQUIRE_APPROVAL",
        Ok(RuleAction::Downgrade) => "DOWNGRADE",
        Ok(RuleAction::Pause) => "PAUSE",
        _ => "UNSPECIFIED",
    }
}

fn policy_rule_to_json(r: &PolicyRule) -> serde_json::Value {
    serde_json::json!({
        "ruleId": r.rule_id,
        "priority": r.priority,
        "targetType": rule_target_type_name(r.target_type),
        "targetSelector": r.target_selector,
        "conditions": prost_struct_to_json(&r.conditions),
        "action": rule_action_name(r.action),
        "actionConfig": prost_struct_to_json(&r.action_config),
        "reasonCode": r.reason_code,
        "enabled": r.enabled,
    })
}

fn baseline_signal_to_json(s: &BaselineSignal) -> serde_json::Value {
    serde_json::json!({
        "name": s.name,
        "score": s.score,
        "dimensions": prost_struct_to_json(&s.dimensions),
    })
}

fn baseline_to_json(b: &Baseline) -> serde_json::Value {
    let signals: Vec<serde_json::Value> = b.signals.iter().map(baseline_signal_to_json).collect();
    serde_json::json!({
        "scope": scope_to_json(&b.scope),
        "signals": signals,
        "computedAt": opt_timestamp(&b.computed_at),
        "modelRevision": b.model_revision,
    })
}

fn candidate_to_json(c: &PolicyCandidate) -> serde_json::Value {
    let proposed_rules: Vec<serde_json::Value> = c
        .proposed_policy
        .as_ref()
        .map(|p| p.rules.iter().map(policy_rule_to_json).collect())
        .unwrap_or_default();
    let source_policy_id = c
        .proposed_policy
        .as_ref()
        .map(|p| p.policy_id.as_str())
        .unwrap_or("");
    let ts = opt_timestamp(&c.generated_at);
    serde_json::json!({
        "candidateId": c.candidate_id,
        "scope": scope_to_json(&c.scope),
        "status": candidate_status_name(c.status),
        "proposedRules": proposed_rules,
        "sourcePolicyId": source_policy_id,
        "createdAt": ts.clone(),
        "updatedAt": ts,
    })
}

fn mode_response_to_json(inner: &GetModeResponse) -> serde_json::Value {
    serde_json::json!({
        "scope": scope_to_json(&inner.scope),
        "mode": learner_mode_to_json(inner.mode),
        "effectiveAt": opt_timestamp(&inner.effective_at),
    })
}

fn set_mode_response_to_json(inner: &SetModeResponse) -> serde_json::Value {
    serde_json::json!({
        "scope": scope_to_json(&inner.scope),
        "mode": learner_mode_to_json(inner.mode),
        "effectiveAt": opt_timestamp(&inner.effective_at),
    })
}

async fn get_learner_mode(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<AppState>,
    Query(q): Query<ScopeQuery>,
) -> Result<axum::response::Response, axum::response::Response> {
    require_permission(&ctx, Permission::LearnerRead).map_err(auth_error_response)?;
    let scope = scope_from_query(&q).map_err(|e| {
        error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            &e,
        )
    })?;
    let proto_req = GetModeRequest { scope: Some(scope) };
    let grpc_req = make_grpc_request(ctx, proto_req);
    let resp = LearnerService::get_mode(&state.learner_svc, grpc_req)
        .await
        .map_err(status_to_rest_error)?;
    let inner = resp.into_inner();
    Ok(ok_json(mode_response_to_json(&inner)))
}

async fn put_learner_mode(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<AppState>,
    Json(body): Json<SetModeBody>,
) -> Result<axum::response::Response, axum::response::Response> {
    require_permission(&ctx, Permission::LearnerWrite).map_err(auth_error_response)?;
    let scope = parse_scope(&body.scope).map_err(|e| {
        error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            &format!("scope: {e}"),
        )
    })?;
    let mode = parse_learner_mode(&body.mode).map_err(|e| {
        error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            &e,
        )
    })?;
    let proto_req = SetModeRequest {
        idempotency: None,
        scope: Some(scope),
        mode,
        comment: body.comment,
    };
    let grpc_req = make_grpc_request(ctx, proto_req);
    let resp = LearnerService::set_mode(&state.learner_svc, grpc_req)
        .await
        .map_err(status_to_rest_error)?;
    let inner = resp.into_inner();
    Ok(ok_json(set_mode_response_to_json(&inner)))
}

async fn get_learner_baseline(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<AppState>,
    Query(q): Query<ScopeQuery>,
) -> Result<axum::response::Response, axum::response::Response> {
    require_permission(&ctx, Permission::LearnerRead).map_err(auth_error_response)?;
    let scope = scope_from_query(&q).map_err(|e| {
        error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            &e,
        )
    })?;
    let proto_req = GetBaselineRequest { scope: Some(scope) };
    let grpc_req = make_grpc_request(ctx, proto_req);
    let resp = LearnerService::get_baseline(&state.learner_svc, grpc_req)
        .await
        .map_err(status_to_rest_error)?;
    let inner: GetBaselineResponse = resp.into_inner();
    let baseline = inner
        .baseline
        .as_ref()
        .ok_or_else(|| status_to_rest_error(tonic::Status::internal("missing baseline")))?;
    Ok(ok_json(serde_json::json!({
        "baseline": baseline_to_json(baseline),
    })))
}

async fn list_learner_candidates(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<AppState>,
    Query(q): Query<ListCandidatesQuery>,
) -> Result<axum::response::Response, axum::response::Response> {
    require_permission(&ctx, Permission::LearnerRead).map_err(auth_error_response)?;
    let scope = scope_from_query(&ScopeQuery {
        scope_type: q.scope_type.clone(),
        scope_id: q.scope_id.clone(),
    })
    .map_err(|e| error_response(StatusCode::BAD_REQUEST, "INVALID_ARGUMENT", &e))?;
    let status_filter = match q.status_filter.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => parse_candidate_status_filter(s).map_err(|e| {
            error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_ARGUMENT",
                &e,
            )
        })?,
        None => CandidateStatus::Unspecified as i32,
    };
    let page = PageRequest {
        page_size: q.page_size.unwrap_or(0),
        page_cursor: q.page_cursor.clone().unwrap_or_default(),
    };
    let proto_req = ListCandidatesRequest {
        page: Some(page),
        scope: Some(scope),
        status_filter,
    };
    let grpc_req = make_grpc_request(ctx, proto_req);
    let resp = LearnerService::list_candidates(&state.learner_svc, grpc_req)
        .await
        .map_err(status_to_rest_error)?;
    let inner: ListCandidatesResponse = resp.into_inner();
    let candidates: Vec<serde_json::Value> = inner
        .candidates
        .iter()
        .map(candidate_to_json)
        .collect();
    Ok(ok_json(serde_json::json!({
        "candidates": candidates,
        "page": page_to_json(&inner.page),
    })))
}

async fn get_learner_candidate(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(candidate_id): Path<Uuid>,
) -> Result<axum::response::Response, axum::response::Response> {
    require_permission(&ctx, Permission::LearnerRead).map_err(auth_error_response)?;
    let proto_req = GetCandidateRequest {
        candidate_id: candidate_id.to_string(),
    };
    let grpc_req = make_grpc_request(ctx, proto_req);
    let resp = LearnerService::get_candidate(&state.learner_svc, grpc_req)
        .await
        .map_err(status_to_rest_error)?;
    let inner: GetCandidateResponse = resp.into_inner();
    let c = inner
        .candidate
        .as_ref()
        .ok_or_else(|| status_to_rest_error(tonic::Status::internal("missing candidate")))?;
    Ok(ok_json(candidate_to_json(c)))
}

async fn approve_learner_candidate(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(candidate_id): Path<Uuid>,
    Json(body): Json<ApproveBody>,
) -> Result<axum::response::Response, axum::response::Response> {
    require_permission(&ctx, Permission::LearnerWrite).map_err(auth_error_response)?;
    let proto_req = ApproveCandidateRequest {
        idempotency: None,
        candidate_id: candidate_id.to_string(),
        approved_by: ctx.principal_id.clone(),
        comment: body.comment,
        activate_as_draft: body.activate_as_draft,
    };
    let grpc_req = make_grpc_request(ctx, proto_req);
    let resp = LearnerService::approve_candidate(&state.learner_svc, grpc_req)
        .await
        .map_err(status_to_rest_error)?;
    let inner: ApproveCandidateResponse = resp.into_inner();
    let candidate = inner
        .candidate
        .as_ref()
        .ok_or_else(|| status_to_rest_error(tonic::Status::internal("missing candidate")))?;
    Ok(ok_json(serde_json::json!({
        "candidate": candidate_to_json(candidate),
        "resultingPolicyId": inner.resulting_policy_id,
    })))
}

async fn reject_learner_candidate(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(candidate_id): Path<Uuid>,
    Json(body): Json<RejectBody>,
) -> Result<axum::response::Response, axum::response::Response> {
    require_permission(&ctx, Permission::LearnerWrite).map_err(auth_error_response)?;
    let comment = if body.reason.trim().is_empty() {
        body.comment
    } else if body.comment.trim().is_empty() {
        body.reason
    } else {
        format!("{}: {}", body.reason.trim(), body.comment)
    };
    let proto_req = RejectCandidateRequest {
        idempotency: None,
        candidate_id: candidate_id.to_string(),
        rejected_by: ctx.principal_id.clone(),
        comment,
    };
    let grpc_req = make_grpc_request(ctx, proto_req);
    let resp = LearnerService::reject_candidate(&state.learner_svc, grpc_req)
        .await
        .map_err(status_to_rest_error)?;
    let inner: RejectCandidateResponse = resp.into_inner();
    let candidate = inner
        .candidate
        .as_ref()
        .ok_or_else(|| status_to_rest_error(tonic::Status::internal("missing candidate")))?;
    Ok(ok_json(serde_json::json!({
        "candidate": candidate_to_json(candidate),
    })))
}

async fn generate_learner(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<AppState>,
    Json(body): Json<GenerateBody>,
) -> Result<axum::response::Response, axum::response::Response> {
    require_permission(&ctx, Permission::LearnerWrite).map_err(auth_error_response)?;
    let scope = parse_scope(&body.scope).map_err(|e| {
        error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            &format!("scope: {e}"),
        )
    })?;
    let generation_hints = body
        .generation_hints
        .as_ref()
        .and_then(json_to_prost_struct);
    let proto_req = GenerateNowRequest {
        idempotency: None,
        scope: Some(scope),
        generation_hints,
    };
    let grpc_req = make_grpc_request(ctx, proto_req);
    let resp = LearnerService::generate_now(&state.learner_svc, grpc_req)
        .await
        .map_err(status_to_rest_error)?;
    let inner: GenerateNowResponse = resp.into_inner();
    Ok(ok_json(serde_json::json!({
        "jobId": inner.job_id,
        "queuedAt": opt_timestamp(&inner.queued_at),
    })))
}
