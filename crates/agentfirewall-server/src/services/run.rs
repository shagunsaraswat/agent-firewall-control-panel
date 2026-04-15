use chrono::{DateTime, Utc};
use prost_types::Timestamp;
use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use sqlx::types::Json;
use sqlx::PgPool;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::proto::common_v1::ScopeType;
use crate::proto::common_v1::{Labels, PageResponse, ResourceScope};
use crate::proto::run_v1::run_service_server::RunService;
use crate::proto::run_v1::{
    BudgetComponent, BudgetState, BudgetUnit, CancelRunRequest, CancelRunResponse,
    CompleteRunRequest, CompleteRunResponse, CompleteStepRequest, CompleteStepResponse,
    CostAttribution, CreateRunRequest, CreateRunResponse, EvaluateStepRequest,
    EvaluateStepResponse, GetBudgetStateRequest, GetBudgetStateResponse, GetRunRequest,
    GetRunResponse, ListRunsRequest, ListRunsResponse, Run, RunStatus,
};

#[derive(Clone)]
pub struct RunServiceImpl {
    pool: PgPool,
    idempotency_ttl_secs: u64,
}

impl RunServiceImpl {
    pub fn new(pool: PgPool, idempotency_ttl_secs: u64) -> Self {
        Self {
            pool,
            idempotency_ttl_secs,
        }
    }
}

#[tonic::async_trait]
impl RunService for RunServiceImpl {
    async fn create_run(
        &self,
        request: Request<CreateRunRequest>,
    ) -> Result<Response<CreateRunResponse>, Status> {
        let (ctx, auth_tenant) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::RunWrite)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        let idempotency_key = crate::idempotency::extract_key_grpc(request.metadata());
        let req = request.into_inner();
        let scope = req
            .scope
            .clone()
            .ok_or_else(|| Status::invalid_argument("scope is required"))?;
        validate_scope(&scope)?;
        crate::auth::verify_scope_tenant(&ctx, &scope.scope_id)?;
        let (_, workspace_id, project_id) = scope_to_row_ids(&scope);

        let agent_id = parse_uuid(&req.agent_id, "agent_id")?;

        let mode = normalize_mode(&req.mode)?;

        let (budget_reserved, budget_estimated, budget_json) = extract_budget(&req.initial_budget)?;

        if let Some(ref key) = idempotency_key {
            match crate::idempotency::check(
                &self.pool,
                auth_tenant,
                "CreateRun",
                key,
                self.idempotency_ttl_secs,
            )
            .await
            {
                Ok(crate::idempotency::IdempotencyCheck::Replay(record)) => {
                    if let Some(ref body) = record.response_body {
                        tracing::info!(key = %key, operation = "CreateRun", "idempotency replay");
                        let msg =
                            crate::idempotency::decode_proto_response::<CreateRunResponse>(body)?;
                        return Ok(Response::new(msg));
                    }
                    tracing::warn!(
                        key = %key,
                        operation = "CreateRun",
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

        let mut metadata = serde_json::json!({});
        if let Some(m) = req.metadata {
            metadata["client"] = struct_to_json(&m);
        }
        if let Some(labels) = req.labels {
            metadata["labels"] = serde_json::to_value(labels.entries).unwrap_or_default();
        }
        if !req.goal.trim().is_empty() {
            metadata["goal"] = serde_json::Value::String(req.goal.clone());
        }
        metadata["budget_state"] = budget_json;

        let run_id = Uuid::new_v4();

        sqlx::query(
            r#"
            INSERT INTO runs (
                id, tenant_id, agent_id, workspace_id, project_id,
                status, mode, budget_usd_reserved, budget_usd_estimated, budget_usd_actual,
                metadata
            )
            VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7, $8, 0, $9::jsonb)
            "#,
        )
        .bind(run_id)
        .bind(auth_tenant)
        .bind(agent_id)
        .bind(workspace_id)
        .bind(project_id)
        .bind(mode)
        .bind(budget_reserved)
        .bind(budget_estimated)
        .bind(metadata)
        .execute(&self.pool)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        let run = load_run(&self.pool, auth_tenant, run_id)
            .await?
            .ok_or_else(|| Status::internal("run missing after insert"))?;

        let resp = CreateRunResponse { run: Some(run) };
        if let Some(ref key) = idempotency_key {
            let body = crate::idempotency::encode_proto_response(&resp);
            if let Err(e) = crate::idempotency::complete(
                &self.pool,
                auth_tenant,
                "CreateRun",
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

    async fn get_run(
        &self,
        request: Request<GetRunRequest>,
    ) -> Result<Response<GetRunResponse>, Status> {
        let (ctx, auth_tenant) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::RunRead)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        let req = request.into_inner();
        let run_id = parse_uuid(&req.run_id, "run_id")?;
        let run = load_run(&self.pool, auth_tenant, run_id)
            .await?
            .ok_or_else(|| Status::not_found("run not found"))?;
        Ok(Response::new(GetRunResponse { run: Some(run) }))
    }

    async fn list_runs(
        &self,
        request: Request<ListRunsRequest>,
    ) -> Result<Response<ListRunsResponse>, Status> {
        let (ctx, _) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::RunRead)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        let req = request.into_inner();
        let scope = req
            .scope
            .clone()
            .ok_or_else(|| Status::invalid_argument("scope is required"))?;
        validate_scope(&scope)?;
        let tenant_id = crate::auth::verify_scope_tenant(&ctx, &scope.scope_id)?;

        let page = req.page.clone().unwrap_or_default();
        let page_size = clamp_page_size(page.page_size);
        let status_filter = if req.status_filter() == RunStatus::Unspecified {
            None
        } else {
            Some(run_status_to_sql(req.status_filter())?)
        };

        let agent_filter = empty_as_none(&req.agent_id)
            .map(|s| parse_uuid(s, "agent_id"))
            .transpose()?;

        let cursor = page
            .page_cursor
            .as_str()
            .trim()
            .is_empty()
            .not()
            .then(|| decode_cursor(&page.page_cursor))
            .transpose()?;

        let rows: Vec<(Uuid, DateTime<Utc>, String)> = match (status_filter, agent_filter, cursor) {
            (None, None, None) => sqlx::query_as(
                r#"
                SELECT id, started_at, status
                FROM runs
                WHERE tenant_id = $1
                ORDER BY started_at DESC, id DESC
                LIMIT $2
                "#,
            )
            .bind(tenant_id)
            .bind(page_size + 1)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Status::internal(e.to_string()))?,
            (Some(st), None, None) => sqlx::query_as(
                r#"
                SELECT id, started_at, status
                FROM runs
                WHERE tenant_id = $1 AND status = $3
                ORDER BY started_at DESC, id DESC
                LIMIT $2
                "#,
            )
            .bind(tenant_id)
            .bind(page_size + 1)
            .bind(st)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Status::internal(e.to_string()))?,
            (None, Some(aid), None) => sqlx::query_as(
                r#"
                SELECT id, started_at, status
                FROM runs
                WHERE tenant_id = $1 AND agent_id = $3
                ORDER BY started_at DESC, id DESC
                LIMIT $2
                "#,
            )
            .bind(tenant_id)
            .bind(page_size + 1)
            .bind(aid)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Status::internal(e.to_string()))?,
            (Some(st), Some(aid), None) => sqlx::query_as(
                r#"
                SELECT id, started_at, status
                FROM runs
                WHERE tenant_id = $1 AND status = $3 AND agent_id = $4
                ORDER BY started_at DESC, id DESC
                LIMIT $2
                "#,
            )
            .bind(tenant_id)
            .bind(page_size + 1)
            .bind(st)
            .bind(aid)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Status::internal(e.to_string()))?,
            (None, None, Some((ts, rid))) => sqlx::query_as(
                r#"
                SELECT id, started_at, status
                FROM runs
                WHERE tenant_id = $1
                  AND (started_at, id) < ($3::timestamptz, $4::uuid)
                ORDER BY started_at DESC, id DESC
                LIMIT $2
                "#,
            )
            .bind(tenant_id)
            .bind(page_size + 1)
            .bind(ts)
            .bind(rid)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Status::internal(e.to_string()))?,
            (Some(st), None, Some((ts, rid))) => sqlx::query_as(
                r#"
                SELECT id, started_at, status
                FROM runs
                WHERE tenant_id = $1 AND status = $5
                  AND (started_at, id) < ($3::timestamptz, $4::uuid)
                ORDER BY started_at DESC, id DESC
                LIMIT $2
                "#,
            )
            .bind(tenant_id)
            .bind(page_size + 1)
            .bind(ts)
            .bind(rid)
            .bind(st)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Status::internal(e.to_string()))?,
            (None, Some(aid), Some((ts, rid))) => sqlx::query_as(
                r#"
                SELECT id, started_at, status
                FROM runs
                WHERE tenant_id = $1 AND agent_id = $5
                  AND (started_at, id) < ($3::timestamptz, $4::uuid)
                ORDER BY started_at DESC, id DESC
                LIMIT $2
                "#,
            )
            .bind(tenant_id)
            .bind(page_size + 1)
            .bind(ts)
            .bind(rid)
            .bind(aid)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Status::internal(e.to_string()))?,
            (Some(st), Some(aid), Some((ts, rid))) => sqlx::query_as(
                r#"
                SELECT id, started_at, status
                FROM runs
                WHERE tenant_id = $1 AND status = $5 AND agent_id = $6
                  AND (started_at, id) < ($3::timestamptz, $4::uuid)
                ORDER BY started_at DESC, id DESC
                LIMIT $2
                "#,
            )
            .bind(tenant_id)
            .bind(page_size + 1)
            .bind(ts)
            .bind(rid)
            .bind(st)
            .bind(aid)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Status::internal(e.to_string()))?,
        };

        let has_more = rows.len() as i64 > page_size;
        let mut page_rows = rows;
        if has_more {
            page_rows.pop();
        }

        let mut runs = Vec::with_capacity(page_rows.len());
        for (rid, _, _) in &page_rows {
            let r = load_run(&self.pool, tenant_id, *rid)
                .await?
                .ok_or_else(|| Status::internal("run row missing"))?;
            runs.push(r);
        }

        let next_cursor = if has_more {
            if let Some((last_id, last_started, _)) = page_rows.last() {
                encode_cursor(*last_started, *last_id)
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        Ok(Response::new(ListRunsResponse {
            runs,
            page: Some(PageResponse {
                next_page_cursor: next_cursor,
                has_more,
                total_estimate: -1,
            }),
        }))
    }

    async fn complete_run(
        &self,
        request: Request<CompleteRunRequest>,
    ) -> Result<Response<CompleteRunResponse>, Status> {
        let (ctx, auth_tenant) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::RunWrite)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        let req = request.into_inner();
        let run_id = parse_uuid(&req.run_id, "run_id")?;
        let terminal = req.terminal_status();
        let status_sql = match terminal {
            RunStatus::Completed => "completed",
            RunStatus::Failed => "failed",
            _ => {
                return Err(Status::invalid_argument(
                    "terminal_status must be COMPLETED or FAILED",
                ));
            }
        };

        let mut patch = serde_json::json!({});
        if let Some(outcome) = req.outcome {
            patch["outcome"] = struct_to_json(&outcome);
        }
        if let Some(ref attr) = req.final_attribution {
            patch["final_attribution"] = serde_json::json!({
                "model": attr.model,
                "tool": attr.tool,
                "estimated_usd": attr.estimated_usd,
                "actual_usd": attr.actual_usd,
                "prompt_tokens": attr.prompt_tokens,
                "completion_tokens": attr.completion_tokens,
            });
        }

        let actual_usd = req
            .final_attribution
            .as_ref()
            .and_then(|a| Decimal::from_f64_retain(a.actual_usd))
            .unwrap_or(Decimal::ZERO);

        let row: Option<(String,)> = sqlx::query_as(
            r#"
            UPDATE runs
            SET status = $3,
                ended_at = now(),
                budget_usd_actual = CASE WHEN $4::numeric > 0 THEN $4 ELSE budget_usd_actual END,
                metadata = metadata || $5::jsonb,
                updated_at = now()
            WHERE id = $1 AND tenant_id = $2 AND status IN ('pending', 'running', 'blocked')
            RETURNING status
            "#,
        )
        .bind(run_id)
        .bind(auth_tenant)
        .bind(status_sql)
        .bind(actual_usd)
        .bind(patch)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        if row.is_none() {
            return Err(Status::failed_precondition(
                "run is not in a completable state (expected pending, running, or blocked)",
            ));
        }

        let run = load_run(&self.pool, auth_tenant, run_id)
            .await?
            .ok_or_else(|| Status::not_found("run not found"))?;

        Ok(Response::new(CompleteRunResponse { run: Some(run) }))
    }

    async fn cancel_run(
        &self,
        request: Request<CancelRunRequest>,
    ) -> Result<Response<CancelRunResponse>, Status> {
        let (ctx, auth_tenant) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::RunWrite)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        let req = request.into_inner();
        let run_id = parse_uuid(&req.run_id, "run_id")?;

        let cancel_meta = serde_json::json!({
            "cancel": {
                "reason_code": req.reason_code,
                "comment": req.comment,
            }
        });

        let row: Option<(String,)> = sqlx::query_as(
            r#"
            UPDATE runs
            SET status = 'cancelled',
                ended_at = now(),
                metadata = metadata || $3::jsonb,
                updated_at = now()
            WHERE id = $1 AND tenant_id = $2 AND status IN ('pending', 'running', 'blocked')
            RETURNING status
            "#,
        )
        .bind(run_id)
        .bind(auth_tenant)
        .bind(cancel_meta)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        if row.is_none() {
            return Err(Status::failed_precondition(
                "run is not in a cancellable state (expected pending, running, or blocked)",
            ));
        }

        let run = load_run(&self.pool, auth_tenant, run_id)
            .await?
            .ok_or_else(|| Status::not_found("run not found"))?;

        Ok(Response::new(CancelRunResponse { run: Some(run) }))
    }

    async fn evaluate_step(
        &self,
        request: Request<EvaluateStepRequest>,
    ) -> Result<Response<EvaluateStepResponse>, Status> {
        let (ctx, tenant_id) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::RunWrite)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        tracing::warn!(
            method = "EvaluateStep",
            tenant_id = %tenant_id,
            server_version = env!("CARGO_PKG_VERSION"),
            "unimplemented gRPC method called"
        );
        Err(Status::unimplemented(format!(
            "EvaluateStep is intentionally deferred (agentfirewall-server {}); no ETA in this release. \
             Use CompleteRun with terminal_status COMPLETED or FAILED for run-level state transitions.",
            env!("CARGO_PKG_VERSION")
        )))
    }

    async fn complete_step(
        &self,
        request: Request<CompleteStepRequest>,
    ) -> Result<Response<CompleteStepResponse>, Status> {
        let (ctx, tenant_id) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::RunWrite)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        tracing::warn!(
            method = "CompleteStep",
            tenant_id = %tenant_id,
            server_version = env!("CARGO_PKG_VERSION"),
            "unimplemented gRPC method called"
        );
        Err(Status::unimplemented(format!(
            "CompleteStep is intentionally deferred (agentfirewall-server {}); no ETA in this release. \
             Use CompleteRun with terminal_status COMPLETED or FAILED for terminal run state changes.",
            env!("CARGO_PKG_VERSION")
        )))
    }

    async fn get_budget_state(
        &self,
        request: Request<GetBudgetStateRequest>,
    ) -> Result<Response<GetBudgetStateResponse>, Status> {
        let (ctx, tenant_id) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::RunRead)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        tracing::warn!(
            method = "GetBudgetState",
            tenant_id = %tenant_id,
            server_version = env!("CARGO_PKG_VERSION"),
            "unimplemented gRPC method called"
        );
        Err(Status::unimplemented(format!(
            "GetBudgetState is intentionally deferred (agentfirewall-server {}); no ETA in this release. \
             Read the budget field returned by GetRun (merged from run columns and metadata).",
            env!("CARGO_PKG_VERSION")
        )))
    }
}

trait BoolExt {
    fn not(self) -> bool;
}

impl BoolExt for bool {
    fn not(self) -> bool {
        !self
    }
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

fn parse_uuid(s: &str, field: &'static str) -> Result<Uuid, Status> {
    Uuid::parse_str(s.trim()).map_err(|e| Status::invalid_argument(format!("{field}: {e}")))
}

fn validate_scope(scope: &ResourceScope) -> Result<(), Status> {
    if scope.scope_type() == ScopeType::Unspecified {
        return Err(Status::invalid_argument("scope.scope_type is required"));
    }
    if scope.scope_id.trim().is_empty() {
        return Err(Status::invalid_argument("scope.scope_id is required"));
    }
    let _ = parse_uuid(&scope.scope_id, "scope.scope_id")?;
    Ok(())
}

fn scope_to_row_ids(scope: &ResourceScope) -> (Uuid, Option<Uuid>, Option<Uuid>) {
    let sid = Uuid::parse_str(scope.scope_id.trim()).unwrap_or_else(|_| Uuid::nil());
    match scope.scope_type() {
        ScopeType::Org => (sid, None, None),
        ScopeType::Workspace => (sid, Some(sid), None),
        ScopeType::Project => (sid, None, Some(sid)),
        ScopeType::Agent | ScopeType::Unspecified => (sid, None, None),
    }
}

fn normalize_mode(raw: &str) -> Result<&'static str, Status> {
    let m = raw.trim();
    if m.is_empty() {
        return Ok("enforce");
    }
    match m {
        "monitor" => Ok("monitor"),
        "enforce" => Ok("enforce"),
        "standalone" => Ok("standalone"),
        _ => Err(Status::invalid_argument(
            "mode must be monitor, enforce, or standalone",
        )),
    }
}

fn run_status_to_sql(s: RunStatus) -> Result<&'static str, Status> {
    match s {
        RunStatus::Pending => Ok("pending"),
        RunStatus::Running => Ok("running"),
        RunStatus::Completed => Ok("completed"),
        RunStatus::Failed => Ok("failed"),
        RunStatus::Cancelled => Ok("cancelled"),
        RunStatus::Blocked => Ok("blocked"),
        RunStatus::Unspecified => Err(Status::invalid_argument("invalid status filter")),
    }
}

fn sql_run_status(s: &str) -> RunStatus {
    match s {
        "pending" => RunStatus::Pending,
        "running" => RunStatus::Running,
        "completed" => RunStatus::Completed,
        "failed" => RunStatus::Failed,
        "cancelled" => RunStatus::Cancelled,
        "blocked" => RunStatus::Blocked,
        _ => RunStatus::Unspecified,
    }
}

fn extract_budget(
    budget: &Option<BudgetState>,
) -> Result<(Decimal, Decimal, serde_json::Value), Status> {
    let Some(b) = budget else {
        return Ok((Decimal::ZERO, Decimal::ZERO, serde_json::json!([])));
    };

    let mut reserved = Decimal::ZERO;
    let mut limit = Decimal::ZERO;
    let mut components = Vec::new();

    for c in &b.components {
        let unit = BudgetUnit::try_from(c.unit).unwrap_or(BudgetUnit::Unspecified);
        let comp = serde_json::json!({
            "unit": c.unit,
            "reserved": c.reserved,
            "consumed": c.consumed,
            "limit": c.limit,
        });
        components.push(comp);
        if unit == BudgetUnit::Usd {
            if let Some(r) = Decimal::from_f64_retain(c.reserved) {
                reserved = reserved.max(r);
            }
            if let Some(l) = Decimal::from_f64_retain(c.limit) {
                limit = limit.max(l);
            }
        }
    }

    let estimated = if limit > Decimal::ZERO {
        limit
    } else {
        reserved
    };
    Ok((reserved, estimated, serde_json::Value::Array(components)))
}

fn struct_to_json(s: &prost_types::Struct) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (k, v) in &s.fields {
        map.insert(k.clone(), crate::services::policy::prost_value_to_json(v));
    }
    serde_json::Value::Object(map)
}

fn decode_cursor(s: &str) -> Result<(DateTime<Utc>, Uuid), Status> {
    let raw = base64_decode(s)?;
    let v: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|_| Status::invalid_argument("invalid cursor"))?;
    let started = v
        .get("s")
        .and_then(|x| x.as_str())
        .ok_or_else(|| Status::invalid_argument("cursor"))?;
    let id = v
        .get("i")
        .and_then(|x| x.as_str())
        .ok_or_else(|| Status::invalid_argument("cursor"))?;
    let dt = DateTime::parse_from_rfc3339(started)
        .map_err(|_| Status::invalid_argument("cursor timestamp"))?
        .with_timezone(&Utc);
    let uuid = Uuid::parse_str(id).map_err(|_| Status::invalid_argument("cursor id"))?;
    Ok((dt, uuid))
}

fn encode_cursor(started: DateTime<Utc>, id: Uuid) -> String {
    let v = serde_json::json!({
        "s": started.to_rfc3339(),
        "i": id.to_string(),
    });
    let bytes = serde_json::to_vec(&v).unwrap_or_default();
    base64_encode(&bytes)
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes)
}

fn base64_decode(s: &str) -> Result<Vec<u8>, Status> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(s.trim().as_bytes())
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(s.trim().as_bytes()))
        .map_err(|_| Status::invalid_argument("cursor encoding"))
}

async fn load_run(pool: &PgPool, tenant_id: Uuid, run_id: Uuid) -> Result<Option<Run>, Status> {
    let row: Option<(
        Uuid,
        Uuid,
        Uuid,
        Option<Uuid>,
        Option<Uuid>,
        String,
        String,
        Decimal,
        Decimal,
        Decimal,
        DateTime<Utc>,
        Option<DateTime<Utc>>,
        Json<serde_json::Value>,
    )> = sqlx::query_as(
        r#"
        SELECT
            id, tenant_id, agent_id, workspace_id, project_id,
            status, mode,
            budget_usd_reserved, budget_usd_estimated, budget_usd_actual,
            started_at, ended_at, metadata
        FROM runs
        WHERE id = $1 AND tenant_id = $2
        "#,
    )
    .bind(run_id)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| Status::internal(e.to_string()))?;

    let Some((
        id,
        tenant_id,
        agent_id,
        workspace_id,
        project_id,
        status,
        mode,
        reserved,
        estimated,
        actual,
        started_at,
        ended_at,
        metadata,
    )) = row
    else {
        return Ok(None);
    };

    let metadata = metadata.0;

    let scope_id = project_id.or(workspace_id).unwrap_or(tenant_id).to_string();

    let scope = ResourceScope {
        scope_type: scope_type_from_row(workspace_id, project_id) as i32,
        scope_id,
    };

    let (labels, goal, budget_state, last_attr, meta_struct) = unpack_metadata(&metadata);
    let budget = Some(merge_budget_columns(
        budget_state,
        &reserved,
        &estimated,
        &actual,
    ));

    Ok(Some(Run {
        run_id: id.to_string(),
        scope: Some(scope),
        agent_id: agent_id.to_string(),
        status: sql_run_status(&status) as i32,
        step_index: 0,
        started_at: Some(Timestamp {
            seconds: started_at.timestamp(),
            nanos: started_at.timestamp_subsec_nanos() as i32,
        }),
        ended_at: ended_at.map(|t| Timestamp {
            seconds: t.timestamp(),
            nanos: t.timestamp_subsec_nanos() as i32,
        }),
        budget,
        last_attribution: last_attr,
        labels: Some(labels),
        metadata: meta_struct,
        mode,
        goal,
    }))
}

fn scope_type_from_row(workspace_id: Option<Uuid>, project_id: Option<Uuid>) -> ScopeType {
    if project_id.is_some() {
        ScopeType::Project
    } else if workspace_id.is_some() {
        ScopeType::Workspace
    } else {
        ScopeType::Org
    }
}

fn unpack_metadata(
    metadata: &serde_json::Value,
) -> (
    Labels,
    String,
    Option<BudgetState>,
    Option<CostAttribution>,
    Option<prost_types::Struct>,
) {
    let labels_map: std::collections::HashMap<String, String> = metadata
        .get("labels")
        .and_then(|v| v.as_object())
        .map(|o| {
            o.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    let goal = metadata
        .get("goal")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let budget_state = metadata.get("budget_state").and_then(parse_budget_state);

    let last_attr = metadata
        .get("final_attribution")
        .and_then(parse_cost_attribution);

    let meta_struct = metadata
        .get("client")
        .map(crate::services::policy::json_to_struct);

    (
        Labels {
            entries: labels_map,
        },
        goal,
        budget_state,
        last_attr,
        meta_struct,
    )
}

fn merge_budget_columns(
    state: Option<BudgetState>,
    reserved: &Decimal,
    estimated: &Decimal,
    actual: &Decimal,
) -> BudgetState {
    let usd = BudgetUnit::Usd as i32;
    let mut bs = state.unwrap_or_else(|| BudgetState {
        components: vec![],
        updated_at: Some(Timestamp {
            seconds: Utc::now().timestamp(),
            nanos: Utc::now().timestamp_subsec_nanos() as i32,
        }),
    });
    let reserved_f = reserved.to_f64().unwrap_or(0.0);
    let limit_f = estimated.to_f64().unwrap_or(0.0);
    let consumed_f = actual.to_f64().unwrap_or(0.0);
    if let Some(c) = bs.components.iter_mut().find(|c| c.unit == usd) {
        c.reserved = reserved_f;
        c.limit = limit_f;
        c.consumed = consumed_f;
    } else {
        bs.components.push(BudgetComponent {
            unit: usd,
            reserved: reserved_f,
            consumed: consumed_f,
            limit: limit_f,
        });
    }
    bs.updated_at = Some(Timestamp {
        seconds: Utc::now().timestamp(),
        nanos: Utc::now().timestamp_subsec_nanos() as i32,
    });
    bs
}

fn parse_cost_attribution(v: &serde_json::Value) -> Option<CostAttribution> {
    let o = v.as_object()?;
    Some(CostAttribution {
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
            .get("estimated_usd")
            .and_then(|x| x.as_f64())
            .unwrap_or(0.0),
        actual_usd: o.get("actual_usd").and_then(|x| x.as_f64()).unwrap_or(0.0),
        prompt_tokens: o.get("prompt_tokens").and_then(|x| x.as_i64()).unwrap_or(0),
        completion_tokens: o
            .get("completion_tokens")
            .and_then(|x| x.as_i64())
            .unwrap_or(0),
    })
}

fn parse_budget_state(v: &serde_json::Value) -> Option<BudgetState> {
    let arr = v.as_array()?;
    let mut components = Vec::new();
    for item in arr {
        let unit = item.get("unit").and_then(|x| x.as_i64()).unwrap_or(0) as i32;
        let reserved = item.get("reserved").and_then(|x| x.as_f64()).unwrap_or(0.0);
        let consumed = item.get("consumed").and_then(|x| x.as_f64()).unwrap_or(0.0);
        let limit = item.get("limit").and_then(|x| x.as_f64()).unwrap_or(0.0);
        components.push(crate::proto::run_v1::BudgetComponent {
            unit,
            reserved,
            consumed,
            limit,
        });
    }
    Some(BudgetState {
        components,
        updated_at: Some(Timestamp {
            seconds: Utc::now().timestamp(),
            nanos: Utc::now().timestamp_subsec_nanos() as i32,
        }),
    })
}
