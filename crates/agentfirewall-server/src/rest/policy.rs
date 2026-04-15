use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::{require_permission, AuthContext, Permission};
use crate::proto::common_v1::{PageRequest, ResourceScope, ScopeType};
use crate::proto::policy_v1::{
    ActivatePolicyRequest, CreatePolicyRequest, DeactivatePolicyRequest, DefaultPolicyAction,
    GetPolicyRequest, ListPoliciesRequest, Policy, PolicyRule, PolicyStatus, RuleAction,
    RuleTargetType,
};
use crate::proto::PolicyService;
use crate::rest::bridge::*;
use crate::rest::error::auth_error_response;
use crate::rest::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/policies", post(create_policy).get(list_policies))
        .route("/policies/:policy_id", get(get_policy))
        .route("/policies/:policy_id/activate", post(activate_policy))
        .route("/policies/:policy_id/deactivate", post(deactivate_policy))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListPoliciesQuery {
    scope_type: Option<String>,
    scope_id: Option<String>,
    status_filter: Option<String>,
    name_prefix: Option<String>,
    page_size: Option<i32>,
    page_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetPolicyQuery {
    version: Option<i64>,
}

fn policy_status_name(v: i32) -> &'static str {
    match PolicyStatus::try_from(v) {
        Ok(PolicyStatus::Draft) => "DRAFT",
        Ok(PolicyStatus::Active) => "ACTIVE",
        Ok(PolicyStatus::Archived) => "ARCHIVED",
        _ => "UNSPECIFIED",
    }
}

fn default_action_name(v: i32) -> &'static str {
    match DefaultPolicyAction::try_from(v) {
        Ok(DefaultPolicyAction::Allow) => "ALLOW",
        Ok(DefaultPolicyAction::Deny) => "DENY",
        Ok(DefaultPolicyAction::RequireApproval) => "REQUIRE_APPROVAL",
        Ok(DefaultPolicyAction::Downgrade) => "DOWNGRADE",
        Ok(DefaultPolicyAction::Pause) => "PAUSE",
        _ => "UNSPECIFIED",
    }
}

fn rule_target_type_name(v: i32) -> &'static str {
    match RuleTargetType::try_from(v) {
        Ok(RuleTargetType::Model) => "MODEL",
        Ok(RuleTargetType::Tool) => "TOOL",
        Ok(RuleTargetType::WriteAction) => "WRITE_ACTION",
        Ok(RuleTargetType::Delegation) => "DELEGATION",
        Ok(RuleTargetType::Budget) => "BUDGET",
        _ => "UNSPECIFIED",
    }
}

fn rule_action_name(v: i32) -> &'static str {
    match RuleAction::try_from(v) {
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

fn policy_to_json(p: &Policy) -> serde_json::Value {
    serde_json::json!({
        "policyId": p.policy_id,
        "version": p.version,
        "scopeType": scope_type_name(p.scope_type),
        "scopeId": p.scope_id,
        "status": policy_status_name(p.status),
        "defaultAction": default_action_name(p.default_action),
        "name": p.name,
        "description": p.description,
        "rules": p.rules.iter().map(policy_rule_to_json).collect::<Vec<_>>(),
        "labels": labels_to_json(&p.labels),
        "createdBy": p.created_by,
        "createdAt": opt_timestamp(&p.created_at),
        "updatedAt": opt_timestamp(&p.updated_at),
        "etag": p.etag,
    })
}

fn parse_default_policy_action(s: &str) -> Result<i32, tonic::Status> {
    match s.trim().to_uppercase().as_str() {
        "ALLOW" => Ok(DefaultPolicyAction::Allow as i32),
        "DENY" => Ok(DefaultPolicyAction::Deny as i32),
        "REQUIRE_APPROVAL" => Ok(DefaultPolicyAction::RequireApproval as i32),
        "DOWNGRADE" => Ok(DefaultPolicyAction::Downgrade as i32),
        "PAUSE" => Ok(DefaultPolicyAction::Pause as i32),
        "" => Err(tonic::Status::invalid_argument("defaultAction is required")),
        _ => Err(tonic::Status::invalid_argument("invalid defaultAction")),
    }
}

fn parse_policy_status_filter(s: &str) -> Result<i32, tonic::Status> {
    match s.trim().to_uppercase().as_str() {
        "" | "UNSPECIFIED" => Ok(PolicyStatus::Unspecified as i32),
        "DRAFT" => Ok(PolicyStatus::Draft as i32),
        "ACTIVE" => Ok(PolicyStatus::Active as i32),
        "ARCHIVED" => Ok(PolicyStatus::Archived as i32),
        _ => Err(tonic::Status::invalid_argument("invalid statusFilter")),
    }
}

fn parse_rule_target_type(s: &str) -> Result<i32, tonic::Status> {
    match s.trim().to_uppercase().as_str() {
        "MODEL" => Ok(RuleTargetType::Model as i32),
        "TOOL" => Ok(RuleTargetType::Tool as i32),
        "WRITE_ACTION" => Ok(RuleTargetType::WriteAction as i32),
        "DELEGATION" => Ok(RuleTargetType::Delegation as i32),
        "BUDGET" => Ok(RuleTargetType::Budget as i32),
        _ => Err(tonic::Status::invalid_argument("invalid rule targetType")),
    }
}

fn parse_rule_action(s: &str) -> Result<i32, tonic::Status> {
    match s.trim().to_uppercase().as_str() {
        "ALLOW" => Ok(RuleAction::Allow as i32),
        "DENY" => Ok(RuleAction::Deny as i32),
        "REQUIRE_APPROVAL" => Ok(RuleAction::RequireApproval as i32),
        "DOWNGRADE" => Ok(RuleAction::Downgrade as i32),
        "PAUSE" => Ok(RuleAction::Pause as i32),
        _ => Err(tonic::Status::invalid_argument("invalid rule action")),
    }
}

fn parse_policy_rule(v: &serde_json::Value) -> Result<PolicyRule, tonic::Status> {
    let rule_id = json_str_camel(v, "ruleId", "rule_id");
    if rule_id.trim().is_empty() {
        return Err(tonic::Status::invalid_argument("each rule requires ruleId"));
    }
    let priority = v
        .get("priority")
        .and_then(|x| x.as_i64())
        .unwrap_or(0) as i32;
    let target_type_str = json_str_camel(v, "targetType", "target_type");
    let target_type = parse_rule_target_type(&target_type_str)?;
    let target_selector = json_str_camel(v, "targetSelector", "target_selector");
    let conditions = v.get("conditions").and_then(json_to_prost_struct);
    let action_str = json_str_camel(v, "action", "action");
    let action = parse_rule_action(&action_str)?;
    let action_config = v
        .get("actionConfig")
        .or_else(|| v.get("action_config"))
        .and_then(json_to_prost_struct);
    let reason_code = json_str_camel(v, "reasonCode", "reason_code");
    let enabled = json_bool(v, "enabled", "enabled");
    Ok(PolicyRule {
        rule_id,
        priority,
        target_type,
        target_selector,
        conditions,
        action,
        action_config,
        reason_code,
        enabled,
    })
}

fn list_scope_from_query(q: &ListPoliciesQuery) -> Result<ResourceScope, tonic::Status> {
    let scope_type_str = q.scope_type.as_deref().unwrap_or("").trim();
    let scope_id = q.scope_id.as_deref().unwrap_or("").trim();
    if scope_id.is_empty() {
        return Err(tonic::Status::invalid_argument("scopeId is required"));
    }
    let scope_type = match scope_type_str.to_uppercase().as_str() {
        "ORG" | "" => ScopeType::Org,
        "WORKSPACE" => ScopeType::Workspace,
        "PROJECT" => ScopeType::Project,
        "AGENT" => ScopeType::Agent,
        _ => {
            return Err(tonic::Status::invalid_argument(
                "invalid scopeType for listPolicies",
            ));
        }
    };
    Ok(ResourceScope {
        scope_type: scope_type as i32,
        scope_id: scope_id.to_string(),
    })
}

async fn create_policy(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<axum::response::Response, axum::response::Response> {
    require_permission(&ctx, Permission::PolicyWrite).map_err(auth_error_response)?;

    let idempotency_key = crate::idempotency::extract_key_rest(&headers);

    let scope = parse_scope(
        body
            .get("scope")
            .ok_or_else(|| status_to_rest_error(tonic::Status::invalid_argument(
                "scope is required",
            )))?,
    )
    .map_err(|e| status_to_rest_error(tonic::Status::invalid_argument(e)))?;

    let name = json_str_camel(&body, "name", "name");
    let description = json_str_camel(&body, "description", "description");
    let default_action_str = json_str_camel(&body, "defaultAction", "default_action");
    let default_action = parse_default_policy_action(&default_action_str)
        .map_err(status_to_rest_error)?;

    let rules_val = body.get("rules").cloned().unwrap_or(serde_json::json!([]));
    let rules_arr = rules_val
        .as_array()
        .ok_or_else(|| status_to_rest_error(tonic::Status::invalid_argument("rules must be array")))?;
    let mut rules = Vec::with_capacity(rules_arr.len());
    for r in rules_arr {
        rules.push(parse_policy_rule(r).map_err(status_to_rest_error)?);
    }

    let create_as_draft = json_bool(&body, "createAsDraft", "create_as_draft");

    let proto_req = CreatePolicyRequest {
        idempotency: None,
        scope: Some(scope),
        name,
        description,
        default_action,
        rules,
        labels: None,
        create_as_draft,
    };

    let grpc_req = make_grpc_request_with_idempotency(ctx, proto_req, idempotency_key.as_deref());
    let res = PolicyService::create_policy(&state.policy_svc, grpc_req)
        .await
        .map_err(status_to_rest_error)?;
    let policy = res
        .into_inner()
        .policy
        .ok_or_else(|| status_to_rest_error(tonic::Status::internal("missing policy")))?;

    Ok(created_json(serde_json::json!({
        "policy": policy_to_json(&policy),
    })))
}

async fn get_policy(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(policy_id): Path<Uuid>,
    Query(query): Query<GetPolicyQuery>,
) -> Result<axum::response::Response, axum::response::Response> {
    require_permission(&ctx, Permission::PolicyRead).map_err(auth_error_response)?;

    let version = query.version.unwrap_or(0);
    let proto_req = GetPolicyRequest {
        policy_id: policy_id.to_string(),
        version,
    };

    let grpc_req = make_grpc_request(ctx, proto_req);
    let res = PolicyService::get_policy(&state.policy_svc, grpc_req)
        .await
        .map_err(status_to_rest_error)?;
    let policy = res
        .into_inner()
        .policy
        .ok_or_else(|| status_to_rest_error(tonic::Status::internal("missing policy")))?;

    Ok(ok_json(serde_json::json!({
        "policy": policy_to_json(&policy),
    })))
}

async fn list_policies(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<AppState>,
    Query(q): Query<ListPoliciesQuery>,
) -> Result<axum::response::Response, axum::response::Response> {
    require_permission(&ctx, Permission::PolicyRead).map_err(auth_error_response)?;

    let scope = list_scope_from_query(&q).map_err(status_to_rest_error)?;
    let status_filter = match &q.status_filter {
        None => PolicyStatus::Unspecified as i32,
        Some(s) => parse_policy_status_filter(s).map_err(status_to_rest_error)?,
    };
    let name_prefix = q.name_prefix.clone().unwrap_or_default();
    let page = PageRequest {
        page_size: q.page_size.unwrap_or(50),
        page_cursor: q.page_cursor.clone().unwrap_or_default(),
    };

    let proto_req = ListPoliciesRequest {
        page: Some(page),
        scope: Some(scope),
        status_filter,
        name_prefix,
    };

    let grpc_req = make_grpc_request(ctx, proto_req);
    let res = PolicyService::list_policies(&state.policy_svc, grpc_req)
        .await
        .map_err(status_to_rest_error)?;
    let inner = res.into_inner();
    let policies_json: Vec<serde_json::Value> =
        inner.policies.iter().map(policy_to_json).collect();

    Ok(ok_json(serde_json::json!({
        "policies": policies_json,
        "page": page_to_json(&inner.page),
    })))
}

async fn activate_policy(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(policy_id): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> Result<axum::response::Response, axum::response::Response> {
    require_permission(&ctx, Permission::PolicyWrite).map_err(auth_error_response)?;

    let etag = json_str_camel(&body, "etag", "etag");
    let activation_comment =
        json_str_camel(&body, "activationComment", "activation_comment");

    let proto_req = ActivatePolicyRequest {
        idempotency: None,
        policy_id: policy_id.to_string(),
        etag,
        activation_comment,
    };

    let grpc_req = make_grpc_request(ctx, proto_req);
    let res = PolicyService::activate_policy(&state.policy_svc, grpc_req)
        .await
        .map_err(status_to_rest_error)?;
    let policy = res
        .into_inner()
        .policy
        .ok_or_else(|| status_to_rest_error(tonic::Status::internal("missing policy")))?;

    Ok(ok_json(serde_json::json!({
        "policy": policy_to_json(&policy),
    })))
}

async fn deactivate_policy(
    Extension(ctx): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(policy_id): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> Result<axum::response::Response, axum::response::Response> {
    require_permission(&ctx, Permission::PolicyWrite).map_err(auth_error_response)?;

    let etag = json_str_camel(&body, "etag", "etag");
    let deactivation_comment =
        json_str_camel(&body, "deactivationComment", "deactivation_comment");

    let proto_req = DeactivatePolicyRequest {
        idempotency: None,
        policy_id: policy_id.to_string(),
        etag,
        deactivation_comment,
    };

    let grpc_req = make_grpc_request(ctx, proto_req);
    let res = PolicyService::deactivate_policy(&state.policy_svc, grpc_req)
        .await
        .map_err(status_to_rest_error)?;
    let policy = res
        .into_inner()
        .policy
        .ok_or_else(|| status_to_rest_error(tonic::Status::internal("missing policy")))?;

    Ok(ok_json(serde_json::json!({
        "policy": policy_to_json(&policy),
    })))
}
