use base64::Engine;
use chrono::{DateTime, Utc};
use prost_types::Timestamp;
use sqlx::{PgPool, Postgres, QueryBuilder};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::nats::NatsPublisher;
use crate::proto::common_v1::{PageResponse, ResourceScope, ScopeType};
use crate::proto::incident_v1::incident_service_server::IncidentService;
use crate::proto::incident_v1::{
    AcknowledgeIncidentRequest, AcknowledgeIncidentResponse, CreateIncidentRequest,
    CreateIncidentResponse, GetIncidentRequest, GetIncidentResponse, Incident, IncidentSeverity,
    IncidentStatus, ListIncidentsRequest, ListIncidentsResponse, RemediationStep,
    ResolveIncidentRequest, ResolveIncidentResponse,
};
use crate::services::audit::{AuditEntry, AuditLogger};
use crate::services::webhook::WebhookDispatcher;

#[derive(Clone)]
pub struct IncidentServiceImpl {
    pool: PgPool,
    nats: Option<NatsPublisher>,
    webhooks: WebhookDispatcher,
    idempotency_ttl_secs: u64,
}

impl IncidentServiceImpl {
    pub fn new(
        pool: PgPool,
        nats: Option<NatsPublisher>,
        webhooks: WebhookDispatcher,
        idempotency_ttl_secs: u64,
    ) -> Self {
        Self {
            pool,
            nats,
            webhooks,
            idempotency_ttl_secs,
        }
    }
}

#[tonic::async_trait]
impl IncidentService for IncidentServiceImpl {
    async fn create_incident(
        &self,
        request: Request<CreateIncidentRequest>,
    ) -> Result<Response<CreateIncidentResponse>, Status> {
        let (ctx, tenant) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::IncidentWrite)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        let idempotency_key = crate::idempotency::extract_key_grpc(request.metadata());
        let req = request.into_inner();

        let sev = req.severity();
        validate_severity(sev)?;
        if req.reason_code.trim().is_empty() {
            return Err(Status::invalid_argument("reason_code is required"));
        }

        let run_id = if req.run_id.trim().is_empty() {
            None
        } else {
            Some(
                Uuid::parse_str(req.run_id.trim())
                    .map_err(|e| Status::invalid_argument(format!("run_id: {e}")))?,
            )
        };

        if let Some(rid) = run_id {
            let ok: Option<(Uuid,)> =
                sqlx::query_as(r#"SELECT id FROM runs WHERE id = $1 AND tenant_id = $2"#)
                    .bind(rid)
                    .bind(tenant)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(|e| Status::internal(e.to_string()))?;
            if ok.is_none() {
                return Err(Status::not_found("run not found for tenant"));
            }
        }

        let approval_id = if req.approval_id.trim().is_empty() {
            None
        } else {
            Some(
                Uuid::parse_str(req.approval_id.trim())
                    .map_err(|e| Status::invalid_argument(format!("approval_id: {e}")))?,
            )
        };

        if let Some(aid) = approval_id {
            let ok: Option<(Uuid,)> =
                sqlx::query_as(r#"SELECT id FROM approvals WHERE id = $1 AND tenant_id = $2"#)
                    .bind(aid)
                    .bind(tenant)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(|e| Status::internal(e.to_string()))?;
            if ok.is_none() {
                return Err(Status::not_found("approval not found for tenant"));
            }
        }

        if let Some(ref key) = idempotency_key {
            match crate::idempotency::check(
                &self.pool,
                tenant,
                "CreateIncident",
                key,
                self.idempotency_ttl_secs,
            )
            .await
            {
                Ok(crate::idempotency::IdempotencyCheck::Replay(record)) => {
                    if let Some(ref body) = record.response_body {
                        tracing::info!(
                            key = %key,
                            operation = "CreateIncident",
                            "idempotency replay"
                        );
                        let msg =
                            crate::idempotency::decode_proto_response::<CreateIncidentResponse>(
                                body,
                            )?;
                        return Ok(Response::new(msg));
                    }
                    tracing::warn!(
                        key = %key,
                        operation = "CreateIncident",
                        "idempotency replay missing response body"
                    );
                    return Err(Status::internal(
                        "idempotency replay missing cached response body",
                    ));
                }
                Ok(crate::idempotency::IdempotencyCheck::InProgress) => {
                    return Err(Status::aborted(
                        "request with this idempotency key is already being processed",
                    ));
                }
                Ok(crate::idempotency::IdempotencyCheck::New) => {}
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "idempotency check failed; proceeding without idempotency"
                    );
                }
            }
        }

        let severity = severity_to_sql(sev)?;
        let mut detail = serde_json::json!({
            "summary": req.summary,
            "context": req.context.as_ref().map(prost_struct_to_json).unwrap_or(serde_json::Value::Null),
            "remediation_steps": remediation_to_json(&req.remediation),
            "policy_id": req.policy_id,
            "created_by": req.created_by,
            "owner": "",
        });

        if let Some(scope) = req.scope {
            merge_scope_json(&mut detail, &scope)?;
        }

        let id = Uuid::now_v7();
        let title = if req.title.trim().is_empty() {
            format!("incident-{}", &id.to_string()[..8])
        } else {
            req.title.clone()
        };

        sqlx::query(
            r#"
            INSERT INTO incidents (
                id, tenant_id, run_id, approval_id, severity, reason_code, status, title, detail
            )
            VALUES ($1, $2, $3, $4, $5, $6, 'open', $7, $8)
            "#,
        )
        .bind(id)
        .bind(tenant)
        .bind(run_id)
        .bind(approval_id)
        .bind(severity)
        .bind(req.reason_code.trim())
        .bind(&title)
        .bind(detail.clone())
        .execute(&self.pool)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        let incident = load_incident(&self.pool, tenant, id)
            .await?
            .ok_or_else(|| Status::internal("incident missing after insert"))?;

        emit_incident_event(
            self.nats.clone(),
            self.webhooks.clone(),
            tenant,
            "opened",
            &incident,
        );

        let _ = AuditLogger::log(
            &self.pool,
            AuditEntry {
                tenant_id: tenant.to_string(),
                actor: req.created_by.clone(),
                action: "incident.created".into(),
                resource_type: "incident".into(),
                resource_id: id.to_string(),
                detail: serde_json::json!({
                    "reason_code": req.reason_code,
                    "severity": severity,
                }),
                ip_address: None,
            },
        )
        .await;

        let resp = CreateIncidentResponse {
            incident: Some(incident),
        };
        if let Some(ref key) = idempotency_key {
            let body = crate::idempotency::encode_proto_response(&resp);
            if let Err(e) = crate::idempotency::complete(
                &self.pool,
                tenant,
                "CreateIncident",
                key,
                200,
                &body,
            )
            .await
            {
                tracing::warn!(error = %e, "failed to complete idempotency record");
            }
        }

        Ok(Response::new(resp))
    }

    async fn get_incident(
        &self,
        request: Request<GetIncidentRequest>,
    ) -> Result<Response<GetIncidentResponse>, Status> {
        let (ctx, tenant) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::IncidentRead)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        let req = request.into_inner();
        let iid = Uuid::parse_str(req.incident_id.trim())
            .map_err(|e| Status::invalid_argument(format!("incident_id: {e}")))?;

        let incident = load_incident(&self.pool, tenant, iid)
            .await?
            .ok_or_else(|| Status::not_found("incident not found"))?;

        Ok(Response::new(GetIncidentResponse {
            incident: Some(incident),
        }))
    }

    async fn list_incidents(
        &self,
        request: Request<ListIncidentsRequest>,
    ) -> Result<Response<ListIncidentsResponse>, Status> {
        let (ctx, tenant) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::IncidentRead)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        let req = request.into_inner();
        let page = req.page.clone().unwrap_or_default();
        let page_size = clamp_page_size(page.page_size);
        let limit = page_size + 1;

        let status_filter = if req.status_filter() == IncidentStatus::Unspecified {
            None
        } else {
            Some(incident_status_to_sql(req.status_filter())?)
        };

        let severities = severities_at_least_filter(req.severity_at_least());
        let reason_prefix = empty_as_none(&req.reason_code_prefix).map(|s| format!("{s}%"));

        let scope_type = req
            .scope
            .as_ref()
            .filter(|s| s.scope_type() != ScopeType::Unspecified)
            .map(|s| scope_type_to_str(s.scope_type()))
            .transpose()?;

        let scope_id = req
            .scope
            .as_ref()
            .filter(|s| s.scope_type() != ScopeType::Unspecified)
            .map(|s| s.scope_id.trim())
            .filter(|s| !s.is_empty());

        if scope_type.is_some() != scope_id.is_some() {
            return Err(Status::invalid_argument(
                "scope requires both scope_type and scope_id",
            ));
        }

        let cursor = decode_cursor(&page.page_cursor)?;

        let mut qb: QueryBuilder<Postgres> = QueryBuilder::new(
            r#"SELECT id, tenant_id, run_id, approval_id, severity, reason_code, status, title, detail,
                      occurred_at, resolved_at, resolved_by, created_at, updated_at
               FROM incidents WHERE tenant_id = "#,
        );
        qb.push_bind(tenant);

        if let Some(st) = &status_filter {
            qb.push(" AND status = ");
            qb.push_bind(st);
        }

        if let Some(ref sev_list) = severities {
            qb.push(" AND severity = ANY(");
            qb.push_bind(sev_list);
            qb.push(")");
        }

        if let Some(prefix) = &reason_prefix {
            qb.push(" AND reason_code LIKE ");
            qb.push_bind(prefix);
        }

        if let (Some(st), Some(sid)) = (&scope_type, &scope_id) {
            qb.push(" AND detail->'scope'->>'scope_type' = ");
            qb.push_bind(st);
            qb.push(" AND detail->'scope'->>'scope_id' = ");
            qb.push_bind(sid);
        }

        if let Some((c_at, c_id)) = cursor {
            qb.push(" AND (occurred_at, id) < (");
            qb.push_bind(c_at);
            qb.push(", ");
            qb.push_bind(c_id);
            qb.push(")");
        }

        qb.push(" ORDER BY occurred_at DESC, id DESC LIMIT ");
        qb.push_bind(limit);

        let rows: Vec<IncidentRow> = qb
            .build_query_as()
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let has_more = rows.len() as i64 > page_size;
        let mut take = rows;
        if has_more {
            take.pop();
        }

        let last_for_cursor = take.last().map(|r| (r.occurred_at, r.id));
        let mut incidents = Vec::with_capacity(take.len());
        for row in take {
            incidents.push(row_to_proto(row)?);
        }

        let next_cursor = if has_more {
            if let Some((occurred, id)) = last_for_cursor {
                encode_cursor(occurred, id)
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        Ok(Response::new(ListIncidentsResponse {
            incidents,
            page: Some(PageResponse {
                next_page_cursor: next_cursor,
                has_more,
                total_estimate: -1,
            }),
        }))
    }

    async fn acknowledge_incident(
        &self,
        request: Request<AcknowledgeIncidentRequest>,
    ) -> Result<Response<AcknowledgeIncidentResponse>, Status> {
        let (ctx, tenant) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::IncidentWrite)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        let req = request.into_inner();
        let iid = Uuid::parse_str(req.incident_id.trim())
            .map_err(|e| Status::invalid_argument(format!("incident_id: {e}")))?;

        let row = fetch_incident_row(&self.pool, tenant, iid)
            .await?
            .ok_or_else(|| Status::not_found("incident not found"))?;

        if !incident_ack_allowed(&row.status) {
            return Err(Status::failed_precondition(
                "only OPEN incidents can be acknowledged",
            ));
        }

        let patch = serde_json::json!({
            "acknowledged_by": req.acknowledged_by,
            "acknowledged_at": Utc::now().to_rfc3339(),
            "ack_comment": req.comment,
        });

        let res = sqlx::query(
            r#"
            UPDATE incidents
            SET status = 'acknowledged',
                detail = detail || $1::jsonb,
                updated_at = now()
            WHERE id = $2 AND tenant_id = $3 AND status = 'open'
            "#,
        )
        .bind(patch)
        .bind(iid)
        .bind(tenant)
        .execute(&self.pool)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        if res.rows_affected() == 0 {
            return Err(Status::failed_precondition(
                "incident is not open or concurrent update",
            ));
        }

        let incident = load_incident(&self.pool, tenant, iid)
            .await?
            .ok_or_else(|| Status::internal("incident missing after acknowledge"))?;

        let _ = AuditLogger::log(
            &self.pool,
            AuditEntry {
                tenant_id: tenant.to_string(),
                actor: req.acknowledged_by.clone(),
                action: "incident.acknowledged".into(),
                resource_type: "incident".into(),
                resource_id: iid.to_string(),
                detail: serde_json::json!({}),
                ip_address: None,
            },
        )
        .await;

        Ok(Response::new(AcknowledgeIncidentResponse {
            incident: Some(incident),
        }))
    }

    async fn resolve_incident(
        &self,
        request: Request<ResolveIncidentRequest>,
    ) -> Result<Response<ResolveIncidentResponse>, Status> {
        let (ctx, tenant) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::IncidentWrite)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        let req = request.into_inner();
        let iid = Uuid::parse_str(req.incident_id.trim())
            .map_err(|e| Status::invalid_argument(format!("incident_id: {e}")))?;

        if req.resolution_summary.trim().is_empty() {
            return Err(Status::invalid_argument(
                "resolution_summary is required (resolution note)",
            ));
        }

        let row = fetch_incident_row(&self.pool, tenant, iid)
            .await?
            .ok_or_else(|| Status::not_found("incident not found"))?;

        if !incident_resolve_allowed(&row.status) {
            return Err(Status::failed_precondition(
                "incident cannot be resolved from current status",
            ));
        }

        let dismissed = req
            .resolution_metadata
            .as_ref()
            .map(prost_struct_to_json)
            .and_then(|v| v.get("dismissed").and_then(|b| b.as_bool()))
            .unwrap_or(false);

        let target_status = if dismissed { "dismissed" } else { "resolved" };

        let resolver = parse_optional_uuid(&req.resolved_by)?;

        let patch = serde_json::json!({
            "resolution_summary": req.resolution_summary,
            "resolution_metadata": req.resolution_metadata.as_ref().map(prost_struct_to_json).unwrap_or(serde_json::Value::Null),
        });

        let res = sqlx::query(
            r#"
            UPDATE incidents
            SET status = $1,
                resolved_at = now(),
                resolved_by = $2,
                detail = detail || $3::jsonb,
                updated_at = now()
            WHERE id = $4 AND tenant_id = $5 AND status IN ('open', 'acknowledged')
            "#,
        )
        .bind(target_status)
        .bind(resolver)
        .bind(patch)
        .bind(iid)
        .bind(tenant)
        .execute(&self.pool)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        if res.rows_affected() == 0 {
            return Err(Status::failed_precondition(
                "incident not in open/acknowledged or concurrent update",
            ));
        }

        let incident = load_incident(&self.pool, tenant, iid)
            .await?
            .ok_or_else(|| Status::internal("incident missing after resolve"))?;

        emit_incident_event(
            self.nats.clone(),
            self.webhooks.clone(),
            tenant,
            "resolved",
            &incident,
        );

        let _ = AuditLogger::log(
            &self.pool,
            AuditEntry {
                tenant_id: tenant.to_string(),
                actor: req.resolved_by.clone(),
                action: "incident.resolved".into(),
                resource_type: "incident".into(),
                resource_id: iid.to_string(),
                detail: serde_json::json!({
                    "status": target_status,
                    "summary": req.resolution_summary,
                }),
                ip_address: None,
            },
        )
        .await;

        Ok(Response::new(ResolveIncidentResponse {
            incident: Some(incident),
        }))
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
#[allow(dead_code)]
struct IncidentRow {
    id: Uuid,
    tenant_id: Uuid,
    run_id: Option<Uuid>,
    approval_id: Option<Uuid>,
    severity: String,
    reason_code: String,
    status: String,
    title: String,
    detail: serde_json::Value,
    occurred_at: DateTime<Utc>,
    resolved_at: Option<DateTime<Utc>>,
    resolved_by: Option<Uuid>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

fn validate_severity(s: IncidentSeverity) -> Result<(), Status> {
    match s {
        IncidentSeverity::Unspecified => Err(Status::invalid_argument("severity is required")),
        _ => Ok(()),
    }
}

fn severity_to_sql(s: IncidentSeverity) -> Result<&'static str, Status> {
    match s {
        IncidentSeverity::Info => Ok("info"),
        IncidentSeverity::Low => Ok("low"),
        IncidentSeverity::Medium => Ok("medium"),
        IncidentSeverity::High => Ok("high"),
        IncidentSeverity::Critical => Ok("critical"),
        IncidentSeverity::Unspecified => Err(Status::invalid_argument("severity")),
    }
}

fn sql_to_incident_severity(s: &str) -> IncidentSeverity {
    match s {
        "info" => IncidentSeverity::Info,
        "low" => IncidentSeverity::Low,
        "medium" => IncidentSeverity::Medium,
        "high" => IncidentSeverity::High,
        "critical" => IncidentSeverity::Critical,
        _ => IncidentSeverity::Unspecified,
    }
}

fn incident_status_to_sql(s: IncidentStatus) -> Result<&'static str, Status> {
    match s {
        IncidentStatus::Open => Ok("open"),
        IncidentStatus::Acknowledged => Ok("acknowledged"),
        IncidentStatus::Resolved => Ok("resolved"),
        IncidentStatus::Dismissed => Ok("dismissed"),
        IncidentStatus::Unspecified => Err(Status::invalid_argument("invalid status filter")),
    }
}

fn sql_to_incident_status(s: &str) -> IncidentStatus {
    match s {
        "open" => IncidentStatus::Open,
        "acknowledged" => IncidentStatus::Acknowledged,
        "resolved" => IncidentStatus::Resolved,
        "dismissed" => IncidentStatus::Dismissed,
        _ => IncidentStatus::Unspecified,
    }
}

fn severities_at_least_filter(min: IncidentSeverity) -> Option<Vec<String>> {
    match min {
        IncidentSeverity::Unspecified => None,
        IncidentSeverity::Info => Some(vec![
            "info".into(),
            "low".into(),
            "medium".into(),
            "high".into(),
            "critical".into(),
        ]),
        IncidentSeverity::Low => Some(vec![
            "low".into(),
            "medium".into(),
            "high".into(),
            "critical".into(),
        ]),
        IncidentSeverity::Medium => Some(vec!["medium".into(), "high".into(), "critical".into()]),
        IncidentSeverity::High => Some(vec!["high".into(), "critical".into()]),
        IncidentSeverity::Critical => Some(vec!["critical".into()]),
    }
}

fn scope_type_to_str(t: ScopeType) -> Result<&'static str, Status> {
    match t {
        ScopeType::Org => Ok("org"),
        ScopeType::Workspace => Ok("workspace"),
        ScopeType::Project => Ok("project"),
        ScopeType::Agent => Ok("agent"),
        ScopeType::Unspecified => Err(Status::invalid_argument("scope_type")),
    }
}

fn merge_scope_json(detail: &mut serde_json::Value, scope: &ResourceScope) -> Result<(), Status> {
    if scope.scope_type() == ScopeType::Unspecified {
        return Ok(());
    }
    let st = scope_type_to_str(scope.scope_type())?;
    let sid = scope.scope_id.trim();
    if sid.is_empty() {
        return Err(Status::invalid_argument("scope.scope_id required"));
    }
    detail["scope"] = serde_json::json!({
        "scope_type": st,
        "scope_id": sid,
    });
    Ok(())
}

fn remediation_to_json(steps: &[RemediationStep]) -> serde_json::Value {
    serde_json::Value::Array(
        steps
            .iter()
            .map(|s| {
                serde_json::json!({
                    "step_id": s.step_id,
                    "title": s.title,
                    "description": s.description,
                    "completed": s.completed,
                    "completed_at": s.completed_at.as_ref().map(ts_rfc3339),
                    "completed_by": s.completed_by,
                })
            })
            .collect(),
    )
}

fn ts_rfc3339(ts: &Timestamp) -> String {
    DateTime::from_timestamp(ts.seconds, ts.nanos.max(0) as u32)
        .map(|d| d.to_rfc3339())
        .unwrap_or_default()
}

fn prost_struct_to_json(s: &prost_types::Struct) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (k, v) in &s.fields {
        map.insert(k.clone(), prost_value_to_json(v));
    }
    serde_json::Value::Object(map)
}

fn prost_value_to_json(v: &prost_types::Value) -> serde_json::Value {
    use prost_types::value::Kind;
    match v.kind.as_ref() {
        Some(Kind::NullValue(_)) => serde_json::Value::Null,
        Some(Kind::NumberValue(n)) => serde_json::json!(*n),
        Some(Kind::StringValue(s)) => serde_json::Value::String(s.clone()),
        Some(Kind::BoolValue(b)) => serde_json::Value::Bool(*b),
        Some(Kind::StructValue(s)) => prost_struct_to_json(s),
        Some(Kind::ListValue(l)) => {
            serde_json::Value::Array(l.values.iter().map(prost_value_to_json).collect())
        }
        None => serde_json::Value::Null,
    }
}

/// OPEN → ACKNOWLEDGED is allowed only from `open`.
pub(crate) fn incident_ack_allowed(current: &str) -> bool {
    current == "open"
}

/// Resolve is allowed from OPEN or ACKNOWLEDGED.
pub(crate) fn incident_resolve_allowed(current: &str) -> bool {
    matches!(current, "open" | "acknowledged")
}

fn clamp_page_size(n: i32) -> i64 {
    if n <= 0 {
        50
    } else {
        (n as i64).min(200)
    }
}

fn empty_as_none(s: &str) -> Option<&str> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

fn decode_cursor(s: &str) -> Result<Option<(DateTime<Utc>, Uuid)>, Status> {
    let t = s.trim();
    if t.is_empty() {
        return Ok(None);
    }
    let raw = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(t.as_bytes())
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(t.as_bytes()))
        .map_err(|_| Status::invalid_argument("invalid page_cursor encoding"))?;
    let v: serde_json::Value = serde_json::from_slice(&raw)
        .map_err(|_| Status::invalid_argument("invalid cursor json"))?;
    let created = v
        .get("c")
        .and_then(|x| x.as_str())
        .ok_or_else(|| Status::invalid_argument("cursor"))?;
    let id = v
        .get("i")
        .and_then(|x| x.as_str())
        .ok_or_else(|| Status::invalid_argument("cursor"))?;
    let dt = DateTime::parse_from_rfc3339(created)
        .map_err(|_| Status::invalid_argument("cursor timestamp"))?
        .with_timezone(&Utc);
    let uuid = Uuid::parse_str(id).map_err(|_| Status::invalid_argument("cursor id"))?;
    Ok(Some((dt, uuid)))
}

fn encode_cursor(created: DateTime<Utc>, id: Uuid) -> String {
    let v = serde_json::json!({
        "c": created.to_rfc3339(),
        "i": id.to_string(),
    });
    let bytes = serde_json::to_vec(&v).unwrap_or_default();
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes)
}

fn parse_optional_uuid(s: &str) -> Result<Option<Uuid>, Status> {
    let t = s.trim();
    if t.is_empty() {
        Ok(None)
    } else {
        Uuid::parse_str(t)
            .map(Some)
            .map_err(|e| Status::invalid_argument(format!("resolved_by: {e}")))
    }
}

async fn fetch_incident_row(
    pool: &PgPool,
    tenant: Uuid,
    id: Uuid,
) -> Result<Option<IncidentRow>, Status> {
    sqlx::query_as::<_, IncidentRow>(
        r#"SELECT id, tenant_id, run_id, approval_id, severity, reason_code, status, title, detail,
                  occurred_at, resolved_at, resolved_by, created_at, updated_at
           FROM incidents WHERE id = $1 AND tenant_id = $2"#,
    )
    .bind(id)
    .bind(tenant)
    .fetch_optional(pool)
    .await
    .map_err(|e| Status::internal(e.to_string()))
}

async fn load_incident(pool: &PgPool, tenant: Uuid, id: Uuid) -> Result<Option<Incident>, Status> {
    let row = fetch_incident_row(pool, tenant, id).await?;
    row.map(row_to_proto).transpose()
}

fn row_to_proto(row: IncidentRow) -> Result<Incident, Status> {
    let d = &row.detail;
    let summary = d
        .get("summary")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let context = d.get("context").and_then(json_to_prost_struct);
    let remediation = json_to_remediation(d.get("remediation_steps"))?;
    let policy_id = d
        .get("policy_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let scope = d.get("scope").and_then(json_to_resource_scope);
    let owner = d
        .get("owner")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let created_by = d
        .get("created_by")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Ok(Incident {
        incident_id: row.id.to_string(),
        severity: sql_to_incident_severity(&row.severity).into(),
        status: sql_to_incident_status(&row.status).into(),
        title: row.title,
        summary,
        reason_code: row.reason_code,
        run_id: row.run_id.map(|u| u.to_string()).unwrap_or_default(),
        policy_id,
        approval_id: row.approval_id.map(|u| u.to_string()).unwrap_or_default(),
        scope,
        context,
        remediation,
        created_by,
        created_at: Some(dt_to_ts(row.created_at)),
        updated_at: Some(dt_to_ts(row.updated_at)),
        owner,
    })
}

fn json_to_resource_scope(v: &serde_json::Value) -> Option<ResourceScope> {
    let obj = v.as_object()?;
    let st = obj.get("scope_type")?.as_str()?;
    let sid = obj.get("scope_id")?.as_str()?;
    let scope_type = match st {
        "org" => ScopeType::Org,
        "workspace" => ScopeType::Workspace,
        "project" => ScopeType::Project,
        "agent" => ScopeType::Agent,
        _ => ScopeType::Unspecified,
    };
    Some(ResourceScope {
        scope_type: scope_type.into(),
        scope_id: sid.to_string(),
    })
}

fn json_to_remediation(v: Option<&serde_json::Value>) -> Result<Vec<RemediationStep>, Status> {
    let Some(arr) = v.and_then(|x| x.as_array()) else {
        return Ok(vec![]);
    };
    let mut out = Vec::new();
    for e in arr {
        let step_id = e
            .get("step_id")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .into();
        let title = e.get("title").and_then(|x| x.as_str()).unwrap_or("").into();
        let description = e
            .get("description")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .into();
        let completed = e
            .get("completed")
            .and_then(|x| x.as_bool())
            .unwrap_or(false);
        let completed_at = e
            .get("completed_at")
            .and_then(|x| x.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| dt_to_ts(d.with_timezone(&Utc)));
        let completed_by = e
            .get("completed_by")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .into();
        out.push(RemediationStep {
            step_id,
            title,
            description,
            completed,
            completed_at,
            completed_by,
        });
    }
    Ok(out)
}

fn json_to_prost_struct(v: &serde_json::Value) -> Option<prost_types::Struct> {
    let obj = v.as_object()?;
    let mut fields = std::collections::BTreeMap::new();
    for (k, val) in obj {
        fields.insert(k.clone(), json_to_prost_value(val));
    }
    Some(prost_types::Struct { fields })
}

fn json_to_prost_value(v: &serde_json::Value) -> prost_types::Value {
    use prost_types::value::Kind;
    let kind = match v {
        serde_json::Value::Null => Kind::NullValue(0),
        serde_json::Value::Bool(b) => Kind::BoolValue(*b),
        serde_json::Value::Number(n) => Kind::NumberValue(n.as_f64().unwrap_or(0.0)),
        serde_json::Value::String(s) => Kind::StringValue(s.clone()),
        serde_json::Value::Array(a) => Kind::ListValue(prost_types::ListValue {
            values: a.iter().map(json_to_prost_value).collect(),
        }),
        serde_json::Value::Object(_) => {
            Kind::StructValue(json_to_prost_struct(v).unwrap_or_default())
        }
    };
    prost_types::Value { kind: Some(kind) }
}

fn dt_to_ts(dt: DateTime<Utc>) -> Timestamp {
    Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    }
}

fn emit_incident_event(
    nats: Option<NatsPublisher>,
    webhooks: WebhookDispatcher,
    tenant: Uuid,
    action: &str,
    incident: &Incident,
) {
    let tid = tenant.to_string();
    let subject = crate::nats::subject(&tid, "incident", action);
    let event_type = format!("incident.{action}");
    let payload = serde_json::json!({
        "incident_id": incident.incident_id,
        "status": incident.status,
        "severity": incident.severity,
        "tenant_id": tid,
    });

    if let Some(nc) = nats {
        let payload_nats = payload.clone();
        tokio::spawn(async move {
            let _ = nc.publish(&subject, &payload_nats).await;
        });
    }

    tokio::spawn(async move {
        webhooks.dispatch(&tid, &event_type, payload).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incident_fsm_ack_only_open() {
        assert!(incident_ack_allowed("open"));
        assert!(!incident_ack_allowed("acknowledged"));
    }

    #[test]
    fn incident_fsm_resolve_from_open_or_ack() {
        assert!(incident_resolve_allowed("open"));
        assert!(incident_resolve_allowed("acknowledged"));
        assert!(!incident_resolve_allowed("resolved"));
    }
}
