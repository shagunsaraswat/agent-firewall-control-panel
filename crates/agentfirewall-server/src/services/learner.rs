//! gRPC `LearnerService`: learner mode, candidates, baselines, and NATS notifications.

use base64::Engine;
use chrono::{DateTime, TimeZone, Utc};
use prost_types::Timestamp;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::nats::NatsPublisher;
use crate::proto::common_v1::{PageResponse, ResourceScope, ScopeType};
use crate::proto::learner_v1::learner_service_server::LearnerService;
use crate::proto::learner_v1::{
    ApproveCandidateRequest, ApproveCandidateResponse, Baseline, BaselineSignal, CandidateStatus,
    GenerateNowRequest, GenerateNowResponse, GetBaselineRequest, GetBaselineResponse,
    GetCandidateRequest, GetCandidateResponse, GetModeRequest, GetModeResponse,
    LearnerMode as LearnerModeProto, ListCandidatesRequest, ListCandidatesResponse,
    PolicyCandidate, RejectCandidateRequest, RejectCandidateResponse, SetModeRequest,
    SetModeResponse,
};
use crate::proto::policy_v1::{
    DefaultPolicyAction, Policy, PolicyRule, PolicyStatus, RuleAction, RuleTargetType,
};
use crate::services::policy::json_to_struct;
use agentfirewall_core::types::BehavioralBaseline;

const MODE_KEY_PREFIX: &str = "av:learner:mode:";

#[derive(Clone)]
pub struct LearnerServiceImpl {
    pool: PgPool,
    redis: Option<redis::aio::ConnectionManager>,
    nats: Option<NatsPublisher>,
}

impl LearnerServiceImpl {
    #[must_use]
    pub fn new(
        pool: PgPool,
        redis: Option<redis::aio::ConnectionManager>,
        nats: Option<NatsPublisher>,
    ) -> Self {
        Self { pool, redis, nats }
    }

    fn mode_key(tenant: Uuid) -> String {
        format!("{MODE_KEY_PREFIX}{tenant}")
    }

    async fn redis_get_mode(&mut self, tenant: Uuid) -> Result<LearnerModeProto, Status> {
        let key = Self::mode_key(tenant);
        let Some(redis) = self.redis.as_mut() else {
            return Ok(LearnerModeProto::ObserveOnly);
        };
        let v: Option<String> = redis
            .get(key)
            .await
            .map_err(|e| Status::internal(format!("redis: {e}")))?;
        Ok(mode_from_redis(v.as_deref()))
    }

    async fn redis_set_mode(&mut self, tenant: Uuid, mode: LearnerModeProto) -> Result<(), Status> {
        let key = Self::mode_key(tenant);
        let s = mode_to_redis(mode)?;
        let Some(redis) = self.redis.as_mut() else {
            return Err(Status::unavailable(
                "Redis is not configured; learner mode cannot be persisted",
            ));
        };
        redis
            .set::<_, _, ()>(&key, s)
            .await
            .map_err(|e| Status::internal(format!("redis: {e}")))?;
        Ok(())
    }
}

fn parse_uuid(s: &str, field: &'static str) -> Result<Uuid, Status> {
    Uuid::parse_str(s.trim()).map_err(|e| Status::invalid_argument(format!("{field}: {e}")))
}

fn validate_scope_for_learner(scope: &ResourceScope) -> Result<(), Status> {
    if scope.scope_type() == ScopeType::Unspecified {
        return Err(Status::invalid_argument("scope.scope_type is required"));
    }
    if scope.scope_id.trim().is_empty() {
        return Err(Status::invalid_argument("scope.scope_id is required"));
    }
    Ok(())
}

fn validate_learner_mode(mode: LearnerModeProto) -> Result<(), Status> {
    if mode == LearnerModeProto::Unspecified {
        return Err(Status::invalid_argument(
            "mode must not be LEARNER_MODE_UNSPECIFIED",
        ));
    }
    Ok(())
}

/// Validates a requested mode transition. Currently rejects only `UNSPECIFIED`.
#[must_use]
pub fn validate_mode_transition(
    _previous: LearnerModeProto,
    new_mode: LearnerModeProto,
) -> Result<(), &'static str> {
    if new_mode == LearnerModeProto::Unspecified {
        return Err("new mode must not be UNSPECIFIED");
    }
    Ok(())
}

fn mode_to_redis(mode: LearnerModeProto) -> Result<&'static str, Status> {
    match mode {
        LearnerModeProto::ObserveOnly => Ok("observe_only"),
        LearnerModeProto::Recommend => Ok("recommend"),
        LearnerModeProto::AutoPromoteSafe => Ok("auto_promote_safe"),
        LearnerModeProto::Unspecified => Err(Status::invalid_argument("invalid mode")),
    }
}

fn mode_from_redis(s: Option<&str>) -> LearnerModeProto {
    match s.unwrap_or("observe_only") {
        "recommend" => LearnerModeProto::Recommend,
        "auto_promote_safe" => LearnerModeProto::AutoPromoteSafe,
        _ => LearnerModeProto::ObserveOnly,
    }
}

fn candidate_status_sql(s: CandidateStatus) -> Option<&'static str> {
    match s {
        CandidateStatus::Proposed => Some("proposed"),
        CandidateStatus::Approved => Some("approved"),
        CandidateStatus::Rejected => Some("rejected"),
        CandidateStatus::Superseded => Some("superseded"),
        CandidateStatus::Unspecified => None,
    }
}

fn candidate_status_proto(s: &str) -> CandidateStatus {
    match s {
        "approved" => CandidateStatus::Approved,
        "rejected" => CandidateStatus::Rejected,
        "superseded" => CandidateStatus::Superseded,
        _ => CandidateStatus::Proposed,
    }
}

#[derive(Serialize, Deserialize)]
struct CandidateCursor {
    created_at: DateTime<Utc>,
    id: Uuid,
}

fn encode_cursor(created_at: DateTime<Utc>, id: Uuid) -> String {
    let c = CandidateCursor { created_at, id };
    let raw = serde_json::to_vec(&c).unwrap_or_default();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

fn decode_cursor(s: &str) -> Result<CandidateCursor, Status> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim().as_bytes())
        .map_err(|_| Status::invalid_argument("invalid page_cursor"))?;
    serde_json::from_slice(&bytes).map_err(|_| Status::invalid_argument("invalid page_cursor"))
}

fn clamp_page_size(n: i32) -> i64 {
    if n <= 0 {
        50
    } else {
        (n as i64).min(200)
    }
}

fn baseline_to_proto(scope: ResourceScope, b: &BehavioralBaseline) -> Baseline {
    let signals = vec![
        BaselineSignal {
            name: "avg_tool_calls".into(),
            score: b.avg_tool_calls,
            dimensions: None,
        },
        BaselineSignal {
            name: "stddev_tool_calls".into(),
            score: b.stddev_tool_calls,
            dimensions: None,
        },
        BaselineSignal {
            name: "avg_model_calls".into(),
            score: b.avg_model_calls,
            dimensions: None,
        },
        BaselineSignal {
            name: "stddev_model_calls".into(),
            score: b.stddev_model_calls,
            dimensions: None,
        },
        BaselineSignal {
            name: "avg_cost_per_run".into(),
            score: f64::from(b.avg_cost_per_run),
            dimensions: None,
        },
        BaselineSignal {
            name: "stddev_cost".into(),
            score: b.stddev_cost,
            dimensions: None,
        },
        BaselineSignal {
            name: "avg_duration_ms".into(),
            score: b.avg_duration_ms,
            dimensions: None,
        },
        BaselineSignal {
            name: "stddev_duration_ms".into(),
            score: b.stddev_duration_ms,
            dimensions: None,
        },
        BaselineSignal {
            name: "sample_runs".into(),
            score: b.sample_runs as f64,
            dimensions: None,
        },
    ];
    Baseline {
        scope: Some(scope),
        signals,
        computed_at: Some(Timestamp {
            seconds: b.updated_at.timestamp(),
            nanos: b.updated_at.timestamp_subsec_nanos() as i32,
        }),
        model_revision: String::new(),
    }
}

fn policy_from_candidate_row(
    id: Uuid,
    tenant: Uuid,
    summary: Option<String>,
    proposed_rules: &serde_json::Value,
    metrics: &serde_json::Value,
) -> Policy {
    let name = metrics
        .get("policy_name")
        .and_then(|v| v.as_str())
        .unwrap_or("learner-candidate")
        .to_owned();
    let policy_id = metrics
        .get("policy_id")
        .and_then(|v| v.as_str())
        .unwrap_or(&id.to_string())
        .to_owned();
    let rules: Vec<PolicyRule> = proposed_rules
        .as_array()
        .map(|arr| arr.iter().filter_map(json_rule_to_policy_rule).collect())
        .unwrap_or_default();
    Policy {
        policy_id,
        version: 0,
        scope_type: ScopeType::Org as i32,
        scope_id: tenant.to_string(),
        status: PolicyStatus::Draft as i32,
        default_action: DefaultPolicyAction::Allow as i32,
        name,
        description: summary.unwrap_or_default(),
        rules,
        labels: None,
        created_by: String::new(),
        created_at: None,
        updated_at: None,
        etag: String::new(),
    }
}

fn json_rule_to_policy_rule(v: &serde_json::Value) -> Option<PolicyRule> {
    let rule_id = v
        .get("rule_id")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_owned();
    if rule_id.is_empty() {
        return None;
    }
    let priority = v.get("priority").and_then(|x| x.as_i64()).unwrap_or(0) as i32;
    let enabled = v.get("enabled").and_then(|x| x.as_bool()).unwrap_or(true);
    let target_type = v
        .get("target_type")
        .and_then(|x| x.as_str())
        .unwrap_or("tool");
    let target_selector = v
        .get("target_selector")
        .map(|x| {
            if let Some(s) = x.as_str() {
                serde_json::json!({ "expr": s }).to_string()
            } else {
                x.to_string()
            }
        })
        .unwrap_or_else(|| "{}".to_owned());
    let action = v.get("action").and_then(|x| x.as_str()).unwrap_or("allow");
    let reason_code = v
        .get("reason_code")
        .and_then(|x| x.as_str())
        .unwrap_or("LEARNER")
        .to_owned();
    let conditions = v
        .get("conditions")
        .filter(|c| c.is_object())
        .map(json_to_struct);
    let action_config = v
        .get("action_config")
        .filter(|c| c.is_object())
        .map(json_to_struct);
    Some(PolicyRule {
        rule_id,
        priority,
        target_type: target_type_str_to_proto(target_type),
        target_selector,
        conditions,
        action: action_str_to_proto(action),
        action_config,
        reason_code,
        enabled,
    })
}

fn target_type_str_to_proto(s: &str) -> i32 {
    match s {
        "model" => RuleTargetType::Model as i32,
        "write_action" => RuleTargetType::WriteAction as i32,
        "delegation" => RuleTargetType::Delegation as i32,
        "budget" => RuleTargetType::Budget as i32,
        _ => RuleTargetType::Tool as i32,
    }
}

fn action_str_to_proto(s: &str) -> i32 {
    match s {
        "deny" => RuleAction::Deny as i32,
        "require_approval" => RuleAction::RequireApproval as i32,
        "downgrade" => RuleAction::Downgrade as i32,
        "pause" => RuleAction::Pause as i32,
        _ => RuleAction::Allow as i32,
    }
}

fn hash_learner_payload(default_action: &str, proposed_rules: &serde_json::Value) -> String {
    let payload = serde_json::json!({
        "default_action": default_action,
        "rules": proposed_rules,
    });
    let bytes = serde_json::to_vec(&payload).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hex::encode(hasher.finalize())
}

fn learner_subject_approved(tenant: &Uuid) -> String {
    format!("agentfirewall.{tenant}.learner.candidate.approved")
}

fn learner_subject_rejected(tenant: &Uuid) -> String {
    format!("agentfirewall.{tenant}.learner.candidate.rejected")
}

async fn promote_proposed_rules(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    proposed_rules: &serde_json::Value,
    metrics: &serde_json::Value,
    activate_as_draft: bool,
) -> Result<Uuid, Status> {
    let default_action = metrics
        .get("default_action")
        .and_then(|v| v.as_str())
        .unwrap_or("allow");
    let policy_id = if let Some(pid) = metrics
        .get("target_policy_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        pid
    } else {
        let new_id = Uuid::new_v4();
        let slug = format!("learner-{}", &new_id.to_string()[..8]);
        sqlx::query(
            r#"INSERT INTO policies (id, tenant_id, name, slug, description)
               VALUES ($1, $2, $3, $4, $5)"#,
        )
        .bind(new_id)
        .bind(tenant_id)
        .bind("Learner promoted policy")
        .bind(&slug)
        .bind(Some("Auto-promoted from learner candidate"))
        .execute(&mut **tx)
        .await
        .map_err(|e| Status::internal(format!("insert policy: {e}")))?;
        new_id
    };

    let max_v: i32 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(version), 0) FROM policy_versions WHERE policy_id = $1",
    )
    .bind(policy_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|e| Status::internal(format!("max version: {e}")))?;
    let next_v = max_v + 1;
    let version_row_id = Uuid::new_v4();
    let status = if activate_as_draft { "draft" } else { "active" };
    let content_sha256 = hash_learner_payload(default_action, proposed_rules);
    let published_at: Option<DateTime<Utc>> = if activate_as_draft {
        None
    } else {
        Some(Utc::now())
    };
    sqlx::query(
        r#"INSERT INTO policy_versions (
            id, policy_id, version, status, default_action, content_sha256,
            effective_from, published_at
        ) VALUES ($1, $2, $3, $4, $5, $6, now(), $7)"#,
    )
    .bind(version_row_id)
    .bind(policy_id)
    .bind(next_v)
    .bind(status)
    .bind(default_action)
    .bind(&content_sha256)
    .bind(published_at)
    .execute(&mut **tx)
    .await
    .map_err(|e| Status::internal(format!("insert policy version: {e}")))?;

    let rules = proposed_rules.as_array().cloned().unwrap_or_default();
    for r in rules {
        let rule_uuid = r
            .get("rule_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok())
            .unwrap_or_else(Uuid::new_v4);
        let rule_key = r
            .get("rule_key")
            .and_then(|v| v.as_str())
            .map_or_else(|| rule_uuid.to_string(), std::borrow::ToOwned::to_owned);
        let priority = r.get("priority").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
        let enabled = r.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
        let target_type = r
            .get("target_type")
            .and_then(|v| v.as_str())
            .unwrap_or("tool");
        let target_selector = r
            .get("target_selector")
            .cloned()
            .unwrap_or(serde_json::json!({}));
        let selector_json = if target_selector.is_string() {
            serde_json::json!({ "expr": target_selector.as_str().unwrap_or("") })
        } else {
            target_selector
        };
        let conditions = r
            .get("conditions")
            .cloned()
            .unwrap_or(serde_json::json!([]));
        let action = r.get("action").and_then(|v| v.as_str()).unwrap_or("allow");
        let action_config = r
            .get("action_config")
            .cloned()
            .unwrap_or(serde_json::json!({}));
        let reason_code = r
            .get("reason_code")
            .and_then(|v| v.as_str())
            .unwrap_or("LEARNER");
        sqlx::query(
            r#"INSERT INTO policy_rules (
                id, policy_version_id, rule_key, priority, enabled,
                target_type, target_selector, conditions, action, action_config, reason_code
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"#,
        )
        .bind(rule_uuid)
        .bind(version_row_id)
        .bind(&rule_key)
        .bind(priority)
        .bind(enabled)
        .bind(target_type)
        .bind(selector_json)
        .bind(conditions)
        .bind(action)
        .bind(action_config)
        .bind(reason_code)
        .execute(&mut **tx)
        .await
        .map_err(|e| Status::internal(format!("insert policy rule: {e}")))?;
    }

    Ok(version_row_id)
}

impl LearnerServiceImpl {
    async fn load_policy_candidate(
        &self,
        id: Uuid,
        tenant_id: Uuid,
    ) -> Result<PolicyCandidate, Status> {
        let row = sqlx::query(
            "SELECT id, tenant_id, status, summary, proposed_rules, metrics, created_at, updated_at
             FROM policy_candidates WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found("candidate not found"))?;
        let tenant_id: Uuid = row
            .try_get("tenant_id")
            .map_err(|e| Status::internal(e.to_string()))?;
        let status_s: String = row
            .try_get("status")
            .map_err(|e| Status::internal(e.to_string()))?;
        let summary: Option<String> = row.try_get("summary").ok();
        let proposed_rules: serde_json::Value = row
            .try_get("proposed_rules")
            .map_err(|e| Status::internal(e.to_string()))?;
        let metrics: serde_json::Value = row
            .try_get("metrics")
            .map_err(|e| Status::internal(e.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|e| Status::internal(e.to_string()))?;
        let policy =
            policy_from_candidate_row(id, tenant_id, summary.clone(), &proposed_rules, &metrics);
        let diff_summary = metrics
            .get("diff_summary")
            .filter(|v| v.is_object())
            .map(json_to_struct);
        let confidence = metrics
            .get("confidence")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let generated_by_job_id = metrics
            .get("generated_by_job_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        Ok(PolicyCandidate {
            candidate_id: id.to_string(),
            scope: Some(ResourceScope {
                scope_type: ScopeType::Org as i32,
                scope_id: tenant_id.to_string(),
            }),
            status: candidate_status_proto(&status_s) as i32,
            proposed_policy: Some(policy),
            diff_summary,
            confidence,
            generated_at: Some(Timestamp {
                seconds: created_at.timestamp(),
                nanos: created_at.timestamp_subsec_nanos() as i32,
            }),
            generated_by_job_id,
        })
    }
}

#[tonic::async_trait]
impl LearnerService for LearnerServiceImpl {
    async fn set_mode(
        &self,
        request: Request<SetModeRequest>,
    ) -> Result<Response<SetModeResponse>, Status> {
        let (ctx, auth_tenant) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::LearnerWrite)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        let req = request.into_inner();
        let scope = req
            .scope
            .clone()
            .ok_or_else(|| Status::invalid_argument("scope is required"))?;
        validate_scope_for_learner(&scope)?;
        crate::auth::verify_scope_tenant(&ctx, &scope.scope_id)?;
        let tenant_id = auth_tenant;
        let new_mode = req.mode();
        validate_learner_mode(new_mode)?;
        let mut this = self.clone();
        let previous = this.redis_get_mode(tenant_id).await?;
        validate_mode_transition(previous, new_mode)
            .map_err(|m| Status::invalid_argument(m.to_string()))?;
        this.redis_set_mode(tenant_id, new_mode).await?;
        Ok(Response::new(SetModeResponse {
            scope: Some(scope),
            mode: new_mode as i32,
            effective_at: Some(Timestamp {
                seconds: Utc::now().timestamp(),
                nanos: 0,
            }),
        }))
    }

    async fn get_mode(
        &self,
        request: Request<GetModeRequest>,
    ) -> Result<Response<GetModeResponse>, Status> {
        let (ctx, auth_tenant) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::LearnerRead)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        let req = request.into_inner();
        let scope = req
            .scope
            .clone()
            .ok_or_else(|| Status::invalid_argument("scope is required"))?;
        validate_scope_for_learner(&scope)?;
        crate::auth::verify_scope_tenant(&ctx, &scope.scope_id)?;
        let tenant_id = auth_tenant;
        let mut this = self.clone();
        let mode = this.redis_get_mode(tenant_id).await?;
        Ok(Response::new(GetModeResponse {
            scope: Some(scope),
            mode: mode as i32,
            effective_at: Some(Timestamp {
                seconds: Utc::now().timestamp(),
                nanos: 0,
            }),
        }))
    }

    async fn get_baseline(
        &self,
        request: Request<GetBaselineRequest>,
    ) -> Result<Response<GetBaselineResponse>, Status> {
        let (ctx, auth_tenant) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::LearnerRead)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        let req = request.into_inner();
        let scope = req
            .scope
            .clone()
            .ok_or_else(|| Status::invalid_argument("scope is required"))?;
        validate_scope_for_learner(&scope)?;
        crate::auth::verify_scope_tenant(&ctx, &scope.scope_id)?;
        let tenant_id = auth_tenant;
        let key = format!("av:baseline:{tenant_id}");
        let mut this = self.clone();
        let raw: Option<String> = match this.redis.as_mut() {
            None => None,
            Some(redis) => redis
                .get(key)
                .await
                .map_err(|e| Status::internal(format!("redis: {e}")))?,
        };
        let baseline = if let Some(json) = raw {
            serde_json::from_str::<BehavioralBaseline>(&json)
                .map(|b| baseline_to_proto(scope.clone(), &b))
                .unwrap_or_else(|_| Baseline {
                    scope: Some(scope.clone()),
                    signals: vec![],
                    computed_at: None,
                    model_revision: String::new(),
                })
        } else {
            Baseline {
                scope: Some(scope.clone()),
                signals: vec![],
                computed_at: None,
                model_revision: String::new(),
            }
        };
        Ok(Response::new(GetBaselineResponse {
            baseline: Some(baseline),
        }))
    }

    async fn list_candidates(
        &self,
        request: Request<ListCandidatesRequest>,
    ) -> Result<Response<ListCandidatesResponse>, Status> {
        let (ctx, auth_tenant) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::LearnerRead)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        let req = request.into_inner();
        let scope = req
            .scope
            .clone()
            .ok_or_else(|| Status::invalid_argument("scope is required"))?;
        validate_scope_for_learner(&scope)?;
        crate::auth::verify_scope_tenant(&ctx, &scope.scope_id)?;
        let tenant_id = auth_tenant;
        let page = req.page.clone().unwrap_or_default();
        let page_size = clamp_page_size(page.page_size);
        let status_filter = candidate_status_sql(req.status_filter());
        let cursor = (!page.page_cursor.as_str().trim().is_empty())
            .then(|| decode_cursor(&page.page_cursor))
            .transpose()?;

        let lim = page_size + 1;
        let rows = match (status_filter, cursor) {
            (None, None) => {
                sqlx::query(
                    r#"SELECT id, tenant_id, status, summary, proposed_rules, metrics, created_at, updated_at
                       FROM policy_candidates WHERE tenant_id = $1
                       ORDER BY created_at DESC, id DESC LIMIT $2"#,
                )
                .bind(tenant_id)
                .bind(lim)
                .fetch_all(&self.pool)
                .await
            }
            (Some(st), None) => {
                sqlx::query(
                    r#"SELECT id, tenant_id, status, summary, proposed_rules, metrics, created_at, updated_at
                       FROM policy_candidates WHERE tenant_id = $1 AND status = $2
                       ORDER BY created_at DESC, id DESC LIMIT $3"#,
                )
                .bind(tenant_id)
                .bind(st)
                .bind(lim)
                .fetch_all(&self.pool)
                .await
            }
            (None, Some(c)) => {
                sqlx::query(
                    r#"SELECT id, tenant_id, status, summary, proposed_rules, metrics, created_at, updated_at
                       FROM policy_candidates WHERE tenant_id = $1
                         AND (created_at, id) < ($2::timestamptz, $3::uuid)
                       ORDER BY created_at DESC, id DESC LIMIT $4"#,
                )
                .bind(tenant_id)
                .bind(c.created_at)
                .bind(c.id)
                .bind(lim)
                .fetch_all(&self.pool)
                .await
            }
            (Some(st), Some(c)) => {
                sqlx::query(
                    r#"SELECT id, tenant_id, status, summary, proposed_rules, metrics, created_at, updated_at
                       FROM policy_candidates WHERE tenant_id = $1 AND status = $2
                         AND (created_at, id) < ($3::timestamptz, $4::uuid)
                       ORDER BY created_at DESC, id DESC LIMIT $5"#,
                )
                .bind(tenant_id)
                .bind(st)
                .bind(c.created_at)
                .bind(c.id)
                .bind(lim)
                .fetch_all(&self.pool)
                .await
            }
        }
        .map_err(|e| Status::internal(format!("list candidates: {e}")))?;

        let mut candidates = Vec::new();
        let mut has_more = false;
        for (i, row) in rows.iter().enumerate() {
            if i as i64 >= page_size {
                has_more = true;
                break;
            }
            let id: Uuid = row
                .try_get("id")
                .map_err(|e| Status::internal(e.to_string()))?;
            let status_s: String = row
                .try_get("status")
                .map_err(|e| Status::internal(e.to_string()))?;
            let summary: Option<String> = row.try_get("summary").ok();
            let proposed_rules: serde_json::Value = row
                .try_get("proposed_rules")
                .map_err(|e| Status::internal(e.to_string()))?;
            let metrics: serde_json::Value = row
                .try_get("metrics")
                .map_err(|e| Status::internal(e.to_string()))?;
            let created_at: DateTime<Utc> = row
                .try_get("created_at")
                .map_err(|e| Status::internal(e.to_string()))?;
            let policy = policy_from_candidate_row(
                id,
                tenant_id,
                summary.clone(),
                &proposed_rules,
                &metrics,
            );
            let diff_summary = metrics
                .get("diff_summary")
                .filter(|v| v.is_object())
                .map(json_to_struct);
            let confidence = metrics
                .get("confidence")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let generated_by_job_id = metrics
                .get("generated_by_job_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            candidates.push(PolicyCandidate {
                candidate_id: id.to_string(),
                scope: Some(ResourceScope {
                    scope_type: ScopeType::Org as i32,
                    scope_id: tenant_id.to_string(),
                }),
                status: candidate_status_proto(&status_s) as i32,
                proposed_policy: Some(policy),
                diff_summary,
                confidence,
                generated_at: Some(Timestamp {
                    seconds: created_at.timestamp(),
                    nanos: created_at.timestamp_subsec_nanos() as i32,
                }),
                generated_by_job_id,
            });
        }

        let next_cursor = if has_more {
            candidates.last().map(|c| {
                let id = Uuid::parse_str(&c.candidate_id).unwrap_or_else(|_| Uuid::nil());
                let ts = c
                    .generated_at
                    .as_ref()
                    .and_then(|t| Utc.timestamp_opt(t.seconds, t.nanos.max(0) as u32).single())
                    .unwrap_or_else(Utc::now);
                encode_cursor(ts, id)
            })
        } else {
            None
        };

        Ok(Response::new(ListCandidatesResponse {
            candidates,
            page: Some(PageResponse {
                next_page_cursor: next_cursor.unwrap_or_default(),
                has_more,
                total_estimate: -1,
            }),
        }))
    }

    async fn get_candidate(
        &self,
        request: Request<GetCandidateRequest>,
    ) -> Result<Response<GetCandidateResponse>, Status> {
        let (ctx, auth_tenant) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::LearnerRead)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        let req = request.into_inner();
        let id = parse_uuid(&req.candidate_id, "candidate_id")?;
        let candidate = self.load_policy_candidate(id, auth_tenant).await?;
        Ok(Response::new(GetCandidateResponse {
            candidate: Some(candidate),
        }))
    }

    async fn approve_candidate(
        &self,
        request: Request<ApproveCandidateRequest>,
    ) -> Result<Response<ApproveCandidateResponse>, Status> {
        let (ctx, auth_tenant) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::LearnerWrite)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        let req = request.into_inner();
        let id = parse_uuid(&req.candidate_id, "candidate_id")?;
        let mut this = self.clone();
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        let row = sqlx::query(
            "SELECT tenant_id, status, proposed_rules, metrics FROM policy_candidates WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
        )
        .bind(id)
        .bind(auth_tenant)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found("candidate not found"))?;
        let tenant_id: Uuid = row
            .try_get("tenant_id")
            .map_err(|e| Status::internal(e.to_string()))?;
        let status: String = row
            .try_get("status")
            .map_err(|e| Status::internal(e.to_string()))?;
        if status != "proposed" {
            return Err(Status::failed_precondition(
                "candidate must be in PROPOSED status",
            ));
        }
        let proposed_rules: serde_json::Value = row
            .try_get("proposed_rules")
            .map_err(|e| Status::internal(e.to_string()))?;
        let metrics: serde_json::Value = row
            .try_get("metrics")
            .map_err(|e| Status::internal(e.to_string()))?;
        let mode = this.redis_get_mode(tenant_id).await?;
        let mut resulting_policy_id = String::new();
        if mode == LearnerModeProto::AutoPromoteSafe {
            let vid = promote_proposed_rules(
                &mut tx,
                tenant_id,
                &proposed_rules,
                &metrics,
                req.activate_as_draft,
            )
            .await?;
            resulting_policy_id = vid.to_string();
        }
        sqlx::query(
            "UPDATE policy_candidates SET status = 'approved', reviewed_at = now(), review_note = $2 WHERE id = $1 AND tenant_id = $3",
        )
        .bind(id)
        .bind(req.comment)
        .bind(auth_tenant)
        .execute(&mut *tx)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        let payload = serde_json::json!({
            "candidate_id": id.to_string(),
            "tenant_id": tenant_id.to_string(),
            "approved_by": req.approved_by,
            "at": Utc::now().to_rfc3339(),
        });
        if let Some(nats) = this.nats.as_ref() {
            nats.publish(&learner_subject_approved(&tenant_id), &payload)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
        }
        let candidate = self.load_policy_candidate(id, auth_tenant).await?;
        Ok(Response::new(ApproveCandidateResponse {
            candidate: Some(candidate),
            resulting_policy_id,
        }))
    }

    async fn reject_candidate(
        &self,
        request: Request<RejectCandidateRequest>,
    ) -> Result<Response<RejectCandidateResponse>, Status> {
        let (ctx, auth_tenant) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::LearnerWrite)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        let req = request.into_inner();
        let id = parse_uuid(&req.candidate_id, "candidate_id")?;
        let this = self.clone();
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        let row = sqlx::query(
            "SELECT tenant_id, status FROM policy_candidates WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
        )
        .bind(id)
        .bind(auth_tenant)
        .fetch_optional(&mut *tx)
                .await
                .map_err(|e| Status::internal(e.to_string()))?
                .ok_or_else(|| Status::not_found("candidate not found"))?;
        let tenant_id: Uuid = row
            .try_get("tenant_id")
            .map_err(|e| Status::internal(e.to_string()))?;
        let status: String = row
            .try_get("status")
            .map_err(|e| Status::internal(e.to_string()))?;
        if status != "proposed" {
            return Err(Status::failed_precondition(
                "candidate must be in PROPOSED status",
            ));
        }
        let note = format!("rejected: {}", req.comment);
        sqlx::query(
            "UPDATE policy_candidates SET status = 'rejected', reviewed_at = now(), review_note = $2 WHERE id = $1 AND tenant_id = $3",
        )
        .bind(id)
        .bind(note)
        .bind(auth_tenant)
        .execute(&mut *tx)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        let payload = serde_json::json!({
            "candidate_id": id.to_string(),
            "tenant_id": tenant_id.to_string(),
            "rejected_by": req.rejected_by,
            "at": Utc::now().to_rfc3339(),
        });
        if let Some(nats) = this.nats.as_ref() {
            nats.publish(&learner_subject_rejected(&tenant_id), &payload)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
        }
        let candidate = self.load_policy_candidate(id, auth_tenant).await?;
        Ok(Response::new(RejectCandidateResponse {
            candidate: Some(candidate),
        }))
    }

    async fn generate_now(
        &self,
        request: Request<GenerateNowRequest>,
    ) -> Result<Response<GenerateNowResponse>, Status> {
        let (ctx, auth_tenant) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::LearnerWrite)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        let req = request.into_inner();
        let scope = req
            .scope
            .clone()
            .ok_or_else(|| Status::invalid_argument("scope is required"))?;
        validate_scope_for_learner(&scope)?;
        crate::auth::verify_scope_tenant(&ctx, &scope.scope_id)?;
        let tenant_id = auth_tenant;
        let job_id = Uuid::new_v4();
        let this = self.clone();
        let payload = serde_json::json!({
            "job_id": job_id.to_string(),
            "tenant_id": tenant_id.to_string(),
            "queued_at": Utc::now().to_rfc3339(),
        });
        let subject = format!("agentfirewall.{tenant_id}.learner.generate.requested");
        let Some(nats) = this.nats.as_ref() else {
            return Err(Status::unavailable(
                "NATS is not configured; cannot queue learner generation",
            ));
        };
        nats.publish(&subject, &payload)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(GenerateNowResponse {
            job_id: job_id.to_string(),
            queued_at: Some(Timestamp {
                seconds: Utc::now().timestamp(),
                nanos: 0,
            }),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_mode_rejects_unspecified() {
        assert!(validate_learner_mode(LearnerModeProto::Unspecified).is_err());
        assert!(validate_learner_mode(LearnerModeProto::ObserveOnly).is_ok());
    }

    #[test]
    fn validate_mode_transition_smoke() {
        assert!(validate_mode_transition(
            LearnerModeProto::ObserveOnly,
            LearnerModeProto::Recommend
        )
        .is_ok());
        assert!(validate_mode_transition(
            LearnerModeProto::Recommend,
            LearnerModeProto::AutoPromoteSafe
        )
        .is_ok());
        assert!(validate_mode_transition(
            LearnerModeProto::ObserveOnly,
            LearnerModeProto::Unspecified
        )
        .is_err());
    }
}
