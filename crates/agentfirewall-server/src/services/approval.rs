use std::time::Duration;

use agentfirewall_core::types::WitnessHash;
use agentfirewall_witness::hash::constant_time_compare;
use base64::Engine;
use chrono::{DateTime, Utc};
use prost_types::Timestamp;
use sqlx::{PgPool, Postgres, QueryBuilder};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::nats::NatsPublisher;
use crate::proto::approval_v1::approval_service_server::ApprovalService;
use crate::proto::approval_v1::{
    Approval, ApprovalStatus, CreateApprovalRequest, CreateApprovalResponse, GetApprovalRequest,
    GetApprovalResponse, ListApprovalsRequest, ListApprovalsResponse, ResolveApprovalRequest,
    ResolveApprovalResponse, RevalidateApprovalRequest, RevalidateApprovalResponse, WitnessBundle,
};
use crate::proto::common_v1::PageResponse;
use crate::services::audit::{AuditEntry, AuditLogger};
use crate::services::webhook::WebhookDispatcher;

#[derive(Clone)]
pub struct ApprovalServiceImpl {
    pool: PgPool,
    nats: Option<NatsPublisher>,
    webhooks: WebhookDispatcher,
    idempotency_ttl_secs: u64,
}

impl ApprovalServiceImpl {
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
impl ApprovalService for ApprovalServiceImpl {
    async fn create_approval(
        &self,
        request: Request<CreateApprovalRequest>,
    ) -> Result<Response<CreateApprovalResponse>, Status> {
        let (ctx, tenant) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::ApprovalWrite)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        let idempotency_key = crate::idempotency::extract_key_grpc(request.metadata());
        let req = request.into_inner();

        let witness = req
            .witness
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("witness is required"))?;
        validate_witness_resource(witness)?;
        let witness_hash = decode_witness_hash(&witness.content_hash)?;

        let run_id = Uuid::parse_str(req.run_id.trim())
            .map_err(|e| Status::invalid_argument(format!("run_id: {e}")))?;

        let row: Option<(Uuid,)> =
            sqlx::query_as(r#"SELECT id FROM runs WHERE id = $1 AND tenant_id = $2"#)
                .bind(run_id)
                .bind(tenant)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
        if row.is_none() {
            return Err(Status::not_found("run not found for tenant"));
        }

        if let Some(ref key) = idempotency_key {
            match crate::idempotency::check(
                &self.pool,
                tenant,
                "CreateApproval",
                key,
                self.idempotency_ttl_secs,
            )
            .await
            {
                Ok(crate::idempotency::IdempotencyCheck::Replay(record)) => {
                    if let Some(ref body) = record.response_body {
                        tracing::info!(
                            key = %key,
                            operation = "CreateApproval",
                            "idempotency replay"
                        );
                        let msg =
                            crate::idempotency::decode_proto_response::<CreateApprovalResponse>(
                                body,
                            )?;
                        return Ok(Response::new(msg));
                    }
                    tracing::warn!(
                        key = %key,
                        operation = "CreateApproval",
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

        let ttl_secs = parse_ttl_seconds(&req.ttl)?;
        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(ttl_secs);

        let requested_action = serde_json::json!({
            "step_index": req.step_index,
            "policy_id": req.policy_id,
            "rule_id": req.rule_id,
            "reason_code": req.reason_code,
            "request_payload": req.request_payload.as_ref().map(prost_struct_to_json).unwrap_or(serde_json::Value::Null),
            "witness": {
                "content_hash": witness.content_hash,
                "cas_uri": witness.cas_uri,
            },
            "requested_by": req.requested_by,
            "ttl": req.ttl,
        });

        let id = Uuid::now_v7();
        let fingerprint = witness.cas_uri.trim().to_string();

        sqlx::query(
            r#"
            INSERT INTO approvals (
                id, tenant_id, run_id, status, witness_hash, resource_fingerprint,
                requested_action, expires_at
            )
            VALUES ($1, $2, $3, 'pending', $4, $5, $6, $7)
            "#,
        )
        .bind(id)
        .bind(tenant)
        .bind(run_id)
        .bind(witness_hash.as_bytes().as_slice())
        .bind(&fingerprint)
        .bind(requested_action.clone())
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        let approval = load_approval_by_id(&self.pool, tenant, id)
            .await?
            .ok_or_else(|| Status::internal("approval missing after insert"))?;

        emit_approval_event(
            self.nats.clone(),
            self.webhooks.clone(),
            tenant,
            "requested",
            &approval,
        );

        let _ = AuditLogger::log(
            &self.pool,
            AuditEntry {
                tenant_id: tenant.to_string(),
                actor: req.requested_by.clone(),
                action: "approval.created".into(),
                resource_type: "approval".into(),
                resource_id: id.to_string(),
                detail: serde_json::json!({ "run_id": run_id.to_string(), "reason_code": req.reason_code }),
                ip_address: None,
            },
        )
        .await;

        let resp = CreateApprovalResponse {
            approval: Some(approval),
        };
        if let Some(ref key) = idempotency_key {
            let body = crate::idempotency::encode_proto_response(&resp);
            if let Err(e) = crate::idempotency::complete(
                &self.pool,
                tenant,
                "CreateApproval",
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

    async fn get_approval(
        &self,
        request: Request<GetApprovalRequest>,
    ) -> Result<Response<GetApprovalResponse>, Status> {
        let (ctx, tenant) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::ApprovalRead)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        let req = request.into_inner();
        let aid = Uuid::parse_str(req.approval_id.trim())
            .map_err(|e| Status::invalid_argument(format!("approval_id: {e}")))?;

        sqlx::query(
            r#"
            UPDATE approvals
            SET status = 'expired', resolved_at = now(), updated_at = now()
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending' AND expires_at < now()
            "#,
        )
        .bind(aid)
        .bind(tenant)
        .execute(&self.pool)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        let approval = load_approval_by_id(&self.pool, tenant, aid)
            .await?
            .ok_or_else(|| Status::not_found("approval not found"))?;

        Ok(Response::new(GetApprovalResponse {
            approval: Some(approval),
        }))
    }

    async fn list_approvals(
        &self,
        request: Request<ListApprovalsRequest>,
    ) -> Result<Response<ListApprovalsResponse>, Status> {
        let (ctx, tenant) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::ApprovalRead)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        let req = request.into_inner();
        let page = req.page.clone().unwrap_or_default();
        let page_size = clamp_page_size(page.page_size);
        let limit = page_size + 1;

        let run_filter = if req.run_id.trim().is_empty() {
            None
        } else {
            Some(
                Uuid::parse_str(req.run_id.trim())
                    .map_err(|e| Status::invalid_argument(format!("run_id: {e}")))?,
            )
        };

        let status_filter = if req.status_filter() == ApprovalStatus::Unspecified {
            None
        } else {
            Some(approval_status_to_sql(req.status_filter())?)
        };

        let cursor = decode_cursor(&page.page_cursor)?;

        let mut qb: QueryBuilder<Postgres> = QueryBuilder::new(
            r#"SELECT id, run_id, status, witness_hash, resource_fingerprint, requested_action,
                      approver_id, resolution_note, created_at, updated_at, expires_at, resolved_at
               FROM approvals WHERE tenant_id = "#,
        );
        qb.push_bind(tenant);

        if let Some(rid) = run_filter {
            qb.push(" AND run_id = ");
            qb.push_bind(rid);
        }
        if let Some(st) = &status_filter {
            qb.push(" AND status = ");
            qb.push_bind(st);
        }
        if let Some((c_at, c_id)) = cursor {
            qb.push(" AND (created_at, id) < (");
            qb.push_bind(c_at);
            qb.push(", ");
            qb.push_bind(c_id);
            qb.push(")");
        }

        qb.push(" ORDER BY created_at DESC, id DESC LIMIT ");
        qb.push_bind(limit);

        let rows: Vec<ApprovalRow> = qb
            .build_query_as()
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let has_more = rows.len() as i64 > page_size;
        let mut take = rows;
        if has_more {
            take.pop();
        }

        let last_for_cursor = take.last().map(|r| (r.created_at, r.id));
        let mut approvals = Vec::with_capacity(take.len());
        for row in take {
            approvals.push(row_to_proto(row)?);
        }

        let next_cursor = if has_more {
            if let Some((created, id)) = last_for_cursor {
                encode_cursor(created, id)
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        Ok(Response::new(ListApprovalsResponse {
            approvals,
            page: Some(PageResponse {
                next_page_cursor: next_cursor,
                has_more,
                total_estimate: -1,
            }),
        }))
    }

    async fn resolve_approval(
        &self,
        request: Request<ResolveApprovalRequest>,
    ) -> Result<Response<ResolveApprovalResponse>, Status> {
        let (ctx, tenant) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::ApprovalWrite)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        let req = request.into_inner();
        let aid = Uuid::parse_str(req.approval_id.trim())
            .map_err(|e| Status::invalid_argument(format!("approval_id: {e}")))?;

        let row = fetch_approval_row(&self.pool, tenant, aid)
            .await?
            .ok_or_else(|| Status::not_found("approval not found"))?;

        if !approval_resolve_transition_allowed(&row.status, req.resolution()) {
            return Err(Status::failed_precondition(
                "invalid approval status transition",
            ));
        }

        let target_sql = resolve_status_to_sql(req.resolution())?;

        if target_sql == "approved" {
            verify_stored_witness_hash(&row)?;
        }

        let approver = parse_optional_uuid(&req.resolved_by)?;

        let res = sqlx::query(
            r#"
            UPDATE approvals
            SET status = $1,
                approver_id = $2,
                resolution_note = $3,
                resolved_at = now(),
                updated_at = now()
            WHERE id = $4 AND tenant_id = $5 AND status = 'pending'
            "#,
        )
        .bind(target_sql)
        .bind(approver)
        .bind(empty_as_none(&req.resolution_comment))
        .bind(aid)
        .bind(tenant)
        .execute(&self.pool)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        if res.rows_affected() == 0 {
            return Err(Status::failed_precondition(
                "approval is not pending or concurrent update",
            ));
        }

        let approval = load_approval_by_id(&self.pool, tenant, aid)
            .await?
            .ok_or_else(|| Status::internal("approval missing after resolve"))?;

        emit_approval_event(
            self.nats.clone(),
            self.webhooks.clone(),
            tenant,
            "resolved",
            &approval,
        );

        let _ = AuditLogger::log(
            &self.pool,
            AuditEntry {
                tenant_id: tenant.to_string(),
                actor: req.resolved_by.clone(),
                action: "approval.resolved".into(),
                resource_type: "approval".into(),
                resource_id: aid.to_string(),
                detail: serde_json::json!({
                    "resolution": format!("{:?}", req.resolution()),
                    "comment": req.resolution_comment,
                }),
                ip_address: None,
            },
        )
        .await;

        Ok(Response::new(ResolveApprovalResponse {
            approval: Some(approval),
        }))
    }

    async fn revalidate_approval(
        &self,
        request: Request<RevalidateApprovalRequest>,
    ) -> Result<Response<RevalidateApprovalResponse>, Status> {
        let (ctx, tenant) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::ApprovalRead)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        let req = request.into_inner();
        let aid = Uuid::parse_str(req.approval_id.trim())
            .map_err(|e| Status::invalid_argument(format!("approval_id: {e}")))?;

        let witness = req
            .witness
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("witness is required"))?;
        if witness.content_hash.trim().is_empty() {
            return Err(Status::invalid_argument("witness.content_hash is required"));
        }
        let new_hash = decode_witness_hash(&witness.content_hash)?;

        let row = fetch_approval_row(&self.pool, tenant, aid)
            .await?
            .ok_or_else(|| Status::not_found("approval not found"))?;

        let stored = witness_hash_from_bytes(&row.witness_hash)
            .map_err(|_| Status::internal("stored witness_hash length invalid"))?;

        let valid = constant_time_compare(&stored, &new_hash);
        let reason_code = if valid {
            String::new()
        } else {
            "WITNESS_HASH_MISMATCH".into()
        };

        let approval = row_to_proto(row)?;

        Ok(Response::new(RevalidateApprovalResponse {
            approval: Some(approval),
            witness_valid: valid,
            reason_code,
        }))
    }
}

/// Periodically marks pending approvals past `expires_at` as `expired`.
pub async fn run_expiry_loop(pool: PgPool, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        let res = sqlx::query(
            r#"
            UPDATE approvals
            SET status = 'expired', resolved_at = now(), updated_at = now()
            WHERE status = 'pending' AND expires_at < now()
            "#,
        )
        .execute(&pool)
        .await;
        if let Err(e) = res {
            tracing::warn!(error=%e, "approval expiry sweep failed");
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
#[allow(dead_code)]
struct ApprovalRow {
    id: Uuid,
    run_id: Uuid,
    status: String,
    witness_hash: Vec<u8>,
    resource_fingerprint: Option<String>,
    requested_action: serde_json::Value,
    approver_id: Option<Uuid>,
    resolution_note: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    resolved_at: Option<DateTime<Utc>>,
}

fn validate_witness_resource(w: &WitnessBundle) -> Result<(), Status> {
    if w.cas_uri.trim().is_empty() {
        return Err(Status::invalid_argument(
            "witness.cas_uri (resource URI) must not be empty",
        ));
    }
    if w.content_hash.trim().is_empty() {
        return Err(Status::invalid_argument(
            "witness.content_hash must not be empty",
        ));
    }
    Ok(())
}

fn decode_witness_hash(hex_str: &str) -> Result<WitnessHash, Status> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| {
        Status::invalid_argument(format!("witness.content_hash is not valid hex: {e}"))
    })?;
    if bytes.len() != 32 {
        return Err(Status::invalid_argument(
            "witness.content_hash must be 32 bytes (64 hex chars)",
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(WitnessHash(arr))
}

fn parse_ttl_seconds(ttl: &str) -> Result<i64, Status> {
    let t = ttl.trim();
    if t.is_empty() {
        return Ok(300);
    }
    let secs = if let Some(rest) = t.strip_suffix('h') {
        rest.trim()
            .parse::<i64>()
            .map_err(|_| Status::invalid_argument("ttl hours"))?
            * 3600
    } else if let Some(rest) = t.strip_suffix('m') {
        rest.trim()
            .parse::<i64>()
            .map_err(|_| Status::invalid_argument("ttl minutes"))?
            * 60
    } else if let Some(rest) = t.strip_suffix('s') {
        rest.trim()
            .parse::<i64>()
            .map_err(|_| Status::invalid_argument("ttl seconds"))?
    } else {
        t.parse::<i64>()
            .map_err(|_| Status::invalid_argument("ttl: use suffix s, m, h or omit for default"))?
    };
    if secs <= 0 {
        return Err(Status::invalid_argument("ttl must be positive"));
    }
    Ok(secs)
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

fn clamp_page_size(n: i32) -> i64 {
    if n <= 0 {
        50
    } else {
        (n as i64).min(200)
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

fn approval_status_to_sql(s: ApprovalStatus) -> Result<&'static str, Status> {
    match s {
        ApprovalStatus::Pending => Ok("pending"),
        ApprovalStatus::Approved => Ok("approved"),
        ApprovalStatus::Rejected => Ok("denied"),
        ApprovalStatus::Expired => Ok("expired"),
        ApprovalStatus::Cancelled => Ok("cancelled"),
        ApprovalStatus::Unspecified => Err(Status::invalid_argument("invalid status filter")),
    }
}

fn sql_to_approval_status(s: &str) -> ApprovalStatus {
    match s {
        "pending" => ApprovalStatus::Pending,
        "approved" => ApprovalStatus::Approved,
        "denied" => ApprovalStatus::Rejected,
        "expired" => ApprovalStatus::Expired,
        "cancelled" => ApprovalStatus::Cancelled,
        _ => ApprovalStatus::Unspecified,
    }
}

fn resolve_status_to_sql(s: ApprovalStatus) -> Result<&'static str, Status> {
    match s {
        ApprovalStatus::Approved => Ok("approved"),
        ApprovalStatus::Rejected => Ok("denied"),
        ApprovalStatus::Cancelled => Ok("cancelled"),
        _ => Err(Status::invalid_argument(
            "resolution must be APPROVED, REJECTED, or CANCELLED",
        )),
    }
}

/// Returns whether a resolve RPC may be applied for the current stored status and target resolution.
pub(crate) fn approval_resolve_transition_allowed(current: &str, target: ApprovalStatus) -> bool {
    if current != "pending" {
        return false;
    }
    matches!(
        target,
        ApprovalStatus::Approved | ApprovalStatus::Rejected | ApprovalStatus::Cancelled
    )
}

fn verify_stored_witness_hash(row: &ApprovalRow) -> Result<(), Status> {
    let content_hash = row
        .requested_action
        .get("witness")
        .and_then(|w| w.get("content_hash"))
        .and_then(|c| c.as_str())
        .ok_or_else(|| Status::failed_precondition("approval payload missing witness hash"))?;
    let expected = decode_witness_hash(content_hash)?;
    let stored = witness_hash_from_bytes(&row.witness_hash)
        .map_err(|_| Status::internal("stored witness_hash invalid"))?;
    if !constant_time_compare(&stored, &expected) {
        return Err(Status::failed_precondition(
            "witness hash check failed for approval",
        ));
    }
    Ok(())
}

fn witness_hash_from_bytes(slice: &[u8]) -> Result<WitnessHash, ()> {
    if slice.len() != 32 {
        return Err(());
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(slice);
    Ok(WitnessHash(a))
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

fn empty_as_none(s: &str) -> Option<&str> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

async fn fetch_approval_row(
    pool: &PgPool,
    tenant: Uuid,
    id: Uuid,
) -> Result<Option<ApprovalRow>, Status> {
    sqlx::query_as::<_, ApprovalRow>(
        r#"SELECT id, run_id, status, witness_hash, resource_fingerprint, requested_action,
                  approver_id, resolution_note, created_at, updated_at, expires_at, resolved_at
           FROM approvals WHERE id = $1 AND tenant_id = $2"#,
    )
    .bind(id)
    .bind(tenant)
    .fetch_optional(pool)
    .await
    .map_err(|e| Status::internal(e.to_string()))
}

async fn load_approval_by_id(
    pool: &PgPool,
    tenant: Uuid,
    id: Uuid,
) -> Result<Option<Approval>, Status> {
    let row = fetch_approval_row(pool, tenant, id).await?;
    row.map(row_to_proto).transpose()
}

fn row_to_proto(row: ApprovalRow) -> Result<Approval, Status> {
    let ra = &row.requested_action;
    let step_index = ra.get("step_index").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
    let policy_id = ra
        .get("policy_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let rule_id = ra
        .get("rule_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let reason_code = ra
        .get("reason_code")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let requested_by = ra
        .get("requested_by")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let request_payload = ra.get("request_payload").and_then(json_to_prost_struct);

    let witness = ra.get("witness").map(|w| WitnessBundle {
        content_hash: w
            .get("content_hash")
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string(),
        cas_uri: w
            .get("cas_uri")
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string(),
    });

    let resolved_by = row.approver_id.map(|u| u.to_string()).unwrap_or_default();

    Ok(Approval {
        approval_id: row.id.to_string(),
        run_id: row.run_id.to_string(),
        step_index,
        status: sql_to_approval_status(&row.status).into(),
        policy_id,
        rule_id,
        reason_code,
        request_payload,
        witness,
        requested_by,
        created_at: Some(dt_to_ts(row.created_at)),
        resolved_at: row.resolved_at.map(dt_to_ts),
        resolved_by,
        resolution_comment: row.resolution_note.unwrap_or_default(),
        expires_at: Some(dt_to_ts(row.expires_at)),
    })
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

fn emit_approval_event(
    nats: Option<NatsPublisher>,
    webhooks: WebhookDispatcher,
    tenant: Uuid,
    action: &str,
    approval: &Approval,
) {
    let tid = tenant.to_string();
    let subject = crate::nats::subject(&tid, "approval", action);
    let event_type = format!("approval.{action}");
    let payload = serde_json::json!({
        "approval_id": approval.approval_id,
        "run_id": approval.run_id,
        "status": approval.status,
        "tenant_id": tid,
    });

    let payload_nats = payload.clone();
    if let Some(nc) = nats {
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
    fn approval_fsm_pending_to_approved() {
        assert!(approval_resolve_transition_allowed(
            "pending",
            ApprovalStatus::Approved
        ));
    }

    #[test]
    fn approval_fsm_rejects_double_resolve() {
        assert!(!approval_resolve_transition_allowed(
            "approved",
            ApprovalStatus::Rejected
        ));
    }

    #[test]
    fn approval_fsm_pending_to_cancelled() {
        assert!(approval_resolve_transition_allowed(
            "pending",
            ApprovalStatus::Cancelled
        ));
    }

    #[test]
    fn ttl_default_empty() {
        assert_eq!(parse_ttl_seconds("").unwrap(), 300);
    }
}
