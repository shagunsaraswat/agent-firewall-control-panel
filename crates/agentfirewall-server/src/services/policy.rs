use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use prost_types::Timestamp;
use sha2::{Digest, Sha256};
use sqlx::types::Json;
use sqlx::PgPool;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::proto::common_v1::{Labels, PageResponse, ResourceScope, ScopeType};
use crate::proto::policy_v1::policy_service_server::PolicyService;
use crate::proto::policy_v1::{
    ActivatePolicyRequest, ActivatePolicyResponse, CreatePolicyRequest, CreatePolicyResponse,
    CreatePolicyVersionRequest, CreatePolicyVersionResponse, DeactivatePolicyRequest,
    DeactivatePolicyResponse, DefaultPolicyAction, GetPolicyRequest, GetPolicyResponse,
    GetPolicyVersionRequest, GetPolicyVersionResponse, ListPoliciesRequest, ListPoliciesResponse,
    ListPolicyVersionsRequest, ListPolicyVersionsResponse, Policy, PolicyRule, PolicyStatus,
    RuleAction, RuleTargetType, UpdatePolicyRequest, UpdatePolicyResponse,
};

#[derive(Clone)]
pub struct PolicyServiceImpl {
    pool: PgPool,
    idempotency_ttl_secs: u64,
}

impl PolicyServiceImpl {
    pub fn new(pool: PgPool, idempotency_ttl_secs: u64) -> Self {
        Self {
            pool,
            idempotency_ttl_secs,
        }
    }
}

#[tonic::async_trait]
impl PolicyService for PolicyServiceImpl {
    async fn create_policy(
        &self,
        request: Request<CreatePolicyRequest>,
    ) -> Result<Response<CreatePolicyResponse>, Status> {
        let (ctx, _auth_tenant) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::PolicyWrite)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        let idempotency_key = crate::idempotency::extract_key_grpc(request.metadata());
        let req = request.into_inner();
        let scope = req
            .scope
            .clone()
            .ok_or_else(|| Status::invalid_argument("scope is required"))?;
        validate_scope(&scope)?;
        let tenant_id = crate::auth::verify_scope_tenant(&ctx, &scope.scope_id)?;

        if req.name.trim().is_empty() {
            return Err(Status::invalid_argument("name must not be empty"));
        }

        let default_action = default_action_to_sql(req.default_action())?;
        let rules = &req.rules;
        for r in rules {
            if r.rule_id.trim().is_empty() {
                return Err(Status::invalid_argument("each rule requires rule_id"));
            }
            if let Err(e) = Uuid::parse_str(&r.rule_id) {
                return Err(Status::invalid_argument(format!("invalid rule_id: {e}")));
            }
        }

        if let Some(ref key) = idempotency_key {
            match crate::idempotency::check(
                &self.pool,
                tenant_id,
                "CreatePolicy",
                key,
                self.idempotency_ttl_secs,
            )
            .await
            {
                Ok(crate::idempotency::IdempotencyCheck::Replay(record)) => {
                    if let Some(ref body) = record.response_body {
                        tracing::info!(
                            key = %key,
                            operation = "CreatePolicy",
                            "idempotency replay"
                        );
                        let msg =
                            crate::idempotency::decode_proto_response::<CreatePolicyResponse>(body)?;
                        return Ok(Response::new(msg));
                    }
                    tracing::warn!(
                        key = %key,
                        operation = "CreatePolicy",
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

        let content_sha256 = hash_policy_document(default_action, rules)?;
        let policy_id = Uuid::new_v4();
        let version_row_id = Uuid::new_v4();
        let slug = unique_slug(&req.name);

        let version_status = if req.create_as_draft {
            "draft"
        } else {
            "active"
        };

        let published_at: Option<DateTime<Utc>> = if version_status == "active" {
            Some(Utc::now())
        } else {
            None
        };

        let effective_from: Option<DateTime<Utc>> = if version_status == "active" {
            Some(Utc::now())
        } else {
            None
        };

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        sqlx::query(
            r#"
            INSERT INTO policies (id, tenant_id, name, slug, description, created_by)
            VALUES ($1, $2, $3, $4, $5, NULL)
            "#,
        )
        .bind(policy_id)
        .bind(tenant_id)
        .bind(&req.name)
        .bind(&slug)
        .bind(empty_as_none(&req.description))
        .execute(&mut *tx)
        .await
        .map_err(|e| map_db_err(e, "create policy"))?;

        sqlx::query(
            r#"
            INSERT INTO policy_versions (
                id, policy_id, version, status, default_action, content_sha256,
                effective_from, published_at
            )
            VALUES ($1, $2, 1, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(version_row_id)
        .bind(policy_id)
        .bind(version_status)
        .bind(default_action)
        .bind(&content_sha256)
        .bind(effective_from)
        .bind(published_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| map_db_err(e, "create policy version"))?;

        for rule in rules {
            let rule_uuid = Uuid::parse_str(&rule.rule_id)
                .map_err(|e| Status::invalid_argument(format!("rule_id: {e}")))?;
            let target_type = target_type_to_sql(rule.target_type())?;
            let action = rule_action_to_sql(rule.action())?;
            let selector_json = serde_json::json!({ "expr": rule.target_selector });
            let conditions = rule
                .conditions
                .as_ref()
                .map(struct_to_json)
                .unwrap_or_else(|| serde_json::json!({}));
            let action_config = rule
                .action_config
                .as_ref()
                .map(struct_to_json)
                .unwrap_or_else(|| serde_json::json!({}));

            sqlx::query(
                r#"
                INSERT INTO policy_rules (
                    id, policy_version_id, rule_key, priority, enabled,
                    target_type, target_selector, conditions, action, action_config, reason_code
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                "#,
            )
            .bind(rule_uuid)
            .bind(version_row_id)
            .bind(&rule.rule_id)
            .bind(rule.priority)
            .bind(rule.enabled)
            .bind(target_type)
            .bind(selector_json)
            .bind(conditions)
            .bind(action)
            .bind(action_config)
            .bind(&rule.reason_code)
            .execute(&mut *tx)
            .await
            .map_err(|e| map_db_err(e, "create policy rule"))?;
        }

        tx.commit()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let policy = load_policy_view(&self.pool, policy_id, Some(1), tenant_id)
            .await?
            .ok_or_else(|| Status::internal("policy not found after insert"))?;

        let resp = CreatePolicyResponse {
            policy: Some(policy),
        };
        if let Some(ref key) = idempotency_key {
            let body = crate::idempotency::encode_proto_response(&resp);
            if let Err(e) = crate::idempotency::complete(
                &self.pool,
                tenant_id,
                "CreatePolicy",
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

    async fn get_policy(
        &self,
        request: Request<GetPolicyRequest>,
    ) -> Result<Response<GetPolicyResponse>, Status> {
        let (ctx, tenant_id) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::PolicyRead)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        let req = request.into_inner();
        let policy_id = parse_uuid(&req.policy_id, "policy_id")?;
        let version = if req.version <= 0 {
            None
        } else {
            Some(req.version as i32)
        };

        let policy = load_policy_view(&self.pool, policy_id, version, tenant_id)
            .await?
            .ok_or_else(|| Status::not_found("policy not found"))?;

        Ok(Response::new(GetPolicyResponse {
            policy: Some(policy),
        }))
    }

    async fn list_policies(
        &self,
        request: Request<ListPoliciesRequest>,
    ) -> Result<Response<ListPoliciesResponse>, Status> {
        let (ctx, _) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::PolicyRead)
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
        let status_filter = if req.status_filter() == PolicyStatus::Unspecified {
            None
        } else {
            Some(policy_status_to_sql(req.status_filter())?)
        };

        let name_prefix = empty_as_none(&req.name_prefix).map(|s| format!("{}%", s));

        let cursor = page
            .page_cursor
            .as_str()
            .trim()
            .is_empty()
            .not()
            .then(|| decode_cursor(&page.page_cursor))
            .transpose()?;

        // Static query branches keep SQL fully parameterized.
        let rows: Vec<(Uuid, DateTime<Utc>, i32, String, String)> = match (
            status_filter.as_ref(),
            name_prefix.as_ref(),
            cursor.as_ref(),
        ) {
            (None, None, None) => sqlx::query_as(
                r#"
                SELECT p.id, p.created_at, lv.version, lv.status, lv.default_action
                FROM policies p
                JOIN LATERAL (
                    SELECT pv.version, pv.status, pv.default_action
                    FROM policy_versions pv
                    WHERE pv.policy_id = p.id
                    ORDER BY pv.version DESC
                    LIMIT 1
                ) lv ON true
                WHERE p.tenant_id = $1 AND p.deleted_at IS NULL
                ORDER BY p.created_at DESC, p.id DESC
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
                SELECT p.id, p.created_at, lv.version, lv.status, lv.default_action
                FROM policies p
                JOIN LATERAL (
                    SELECT pv.version, pv.status, pv.default_action
                    FROM policy_versions pv
                    WHERE pv.policy_id = p.id
                    ORDER BY pv.version DESC
                    LIMIT 1
                ) lv ON true
                WHERE p.tenant_id = $1 AND p.deleted_at IS NULL AND lv.status = $3
                ORDER BY p.created_at DESC, p.id DESC
                LIMIT $2
                "#,
            )
            .bind(tenant_id)
            .bind(page_size + 1)
            .bind(st)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Status::internal(e.to_string()))?,
            (None, Some(np), None) => sqlx::query_as(
                r#"
                SELECT p.id, p.created_at, lv.version, lv.status, lv.default_action
                FROM policies p
                JOIN LATERAL (
                    SELECT pv.version, pv.status, pv.default_action
                    FROM policy_versions pv
                    WHERE pv.policy_id = p.id
                    ORDER BY pv.version DESC
                    LIMIT 1
                ) lv ON true
                WHERE p.tenant_id = $1 AND p.deleted_at IS NULL AND p.name ILIKE $3
                ORDER BY p.created_at DESC, p.id DESC
                LIMIT $2
                "#,
            )
            .bind(tenant_id)
            .bind(page_size + 1)
            .bind(np)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Status::internal(e.to_string()))?,
            (Some(st), Some(np), None) => sqlx::query_as(
                r#"
                SELECT p.id, p.created_at, lv.version, lv.status, lv.default_action
                FROM policies p
                JOIN LATERAL (
                    SELECT pv.version, pv.status, pv.default_action
                    FROM policy_versions pv
                    WHERE pv.policy_id = p.id
                    ORDER BY pv.version DESC
                    LIMIT 1
                ) lv ON true
                WHERE p.tenant_id = $1 AND p.deleted_at IS NULL
                  AND lv.status = $3 AND p.name ILIKE $4
                ORDER BY p.created_at DESC, p.id DESC
                LIMIT $2
                "#,
            )
            .bind(tenant_id)
            .bind(page_size + 1)
            .bind(st)
            .bind(np)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Status::internal(e.to_string()))?,
            (None, None, Some((cc, cid))) => sqlx::query_as(
                r#"
                SELECT p.id, p.created_at, lv.version, lv.status, lv.default_action
                FROM policies p
                JOIN LATERAL (
                    SELECT pv.version, pv.status, pv.default_action
                    FROM policy_versions pv
                    WHERE pv.policy_id = p.id
                    ORDER BY pv.version DESC
                    LIMIT 1
                ) lv ON true
                WHERE p.tenant_id = $1 AND p.deleted_at IS NULL
                  AND (p.created_at, p.id) < ($3::timestamptz, $4::uuid)
                ORDER BY p.created_at DESC, p.id DESC
                LIMIT $2
                "#,
            )
            .bind(tenant_id)
            .bind(page_size + 1)
            .bind(cc)
            .bind(cid)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Status::internal(e.to_string()))?,
            (Some(st), None, Some((cc, cid))) => sqlx::query_as(
                r#"
                SELECT p.id, p.created_at, lv.version, lv.status, lv.default_action
                FROM policies p
                JOIN LATERAL (
                    SELECT pv.version, pv.status, pv.default_action
                    FROM policy_versions pv
                    WHERE pv.policy_id = p.id
                    ORDER BY pv.version DESC
                    LIMIT 1
                ) lv ON true
                WHERE p.tenant_id = $1 AND p.deleted_at IS NULL AND lv.status = $5
                  AND (p.created_at, p.id) < ($3::timestamptz, $4::uuid)
                ORDER BY p.created_at DESC, p.id DESC
                LIMIT $2
                "#,
            )
            .bind(tenant_id)
            .bind(page_size + 1)
            .bind(cc)
            .bind(cid)
            .bind(st)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Status::internal(e.to_string()))?,
            (None, Some(np), Some((cc, cid))) => sqlx::query_as(
                r#"
                SELECT p.id, p.created_at, lv.version, lv.status, lv.default_action
                FROM policies p
                JOIN LATERAL (
                    SELECT pv.version, pv.status, pv.default_action
                    FROM policy_versions pv
                    WHERE pv.policy_id = p.id
                    ORDER BY pv.version DESC
                    LIMIT 1
                ) lv ON true
                WHERE p.tenant_id = $1 AND p.deleted_at IS NULL AND p.name ILIKE $5
                  AND (p.created_at, p.id) < ($3::timestamptz, $4::uuid)
                ORDER BY p.created_at DESC, p.id DESC
                LIMIT $2
                "#,
            )
            .bind(tenant_id)
            .bind(page_size + 1)
            .bind(cc)
            .bind(cid)
            .bind(np)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Status::internal(e.to_string()))?,
            (Some(st), Some(np), Some((cc, cid))) => sqlx::query_as(
                r#"
                SELECT p.id, p.created_at, lv.version, lv.status, lv.default_action
                FROM policies p
                JOIN LATERAL (
                    SELECT pv.version, pv.status, pv.default_action
                    FROM policy_versions pv
                    WHERE pv.policy_id = p.id
                    ORDER BY pv.version DESC
                    LIMIT 1
                ) lv ON true
                WHERE p.tenant_id = $1 AND p.deleted_at IS NULL
                  AND lv.status = $5 AND p.name ILIKE $6
                  AND (p.created_at, p.id) < ($3::timestamptz, $4::uuid)
                ORDER BY p.created_at DESC, p.id DESC
                LIMIT $2
                "#,
            )
            .bind(tenant_id)
            .bind(page_size + 1)
            .bind(cc)
            .bind(cid)
            .bind(st)
            .bind(np)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Status::internal(e.to_string()))?,
        };

        let has_more = rows.len() as i64 > page_size;
        let mut page_rows = rows;
        if has_more {
            page_rows.pop();
        }

        let mut policies = Vec::with_capacity(page_rows.len());
        for (pid, _, _, _, _) in &page_rows {
            let p = load_policy_view(&self.pool, *pid, None, tenant_id)
                .await?
                .ok_or_else(|| Status::internal("policy row missing"))?;
            policies.push(p);
        }

        let next_cursor = if has_more {
            if let Some((last_id, last_created, _, _, _)) = page_rows.last() {
                encode_cursor(*last_created, *last_id)
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        Ok(Response::new(ListPoliciesResponse {
            policies,
            page: Some(PageResponse {
                next_page_cursor: next_cursor,
                has_more,
                total_estimate: -1,
            }),
        }))
    }

    async fn activate_policy(
        &self,
        request: Request<ActivatePolicyRequest>,
    ) -> Result<Response<ActivatePolicyResponse>, Status> {
        let (ctx, tenant_id) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::PolicyWrite)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        let req = request.into_inner();
        let policy_id = parse_uuid(&req.policy_id, "policy_id")?;
        if req.etag.trim().is_empty() {
            return Err(Status::invalid_argument("etag is required"));
        }

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let row: Option<(Uuid,)> = sqlx::query_as(
            r#"
            SELECT pv.id
            FROM policy_versions pv
            INNER JOIN policies p ON p.id = pv.policy_id
            WHERE pv.policy_id = $1
              AND p.tenant_id = $2
              AND p.deleted_at IS NULL
              AND pv.content_sha256 = $3
              AND pv.status IN ('draft', 'archived')
            ORDER BY pv.version DESC
            LIMIT 1
            "#,
        )
        .bind(policy_id)
        .bind(tenant_id)
        .bind(&req.etag)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        let version_pk = row
            .ok_or_else(|| {
                Status::failed_precondition("no matching policy version for etag or already active")
            })?
            .0;

        sqlx::query(
            r#"
            UPDATE policy_versions pv
            SET status = 'archived',
                archived_at = COALESCE(pv.archived_at, now()),
                effective_to = now(),
                updated_at = now()
            FROM policies p
            WHERE pv.policy_id = p.id
              AND p.tenant_id = $3
              AND p.deleted_at IS NULL
              AND pv.policy_id = $1
              AND pv.status = 'active'
              AND pv.id <> $2
            "#,
        )
        .bind(policy_id)
        .bind(version_pk)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        let now = Utc::now();
        let res = sqlx::query(
            r#"
            UPDATE policy_versions pv
            SET status = 'active',
                published_at = $3,
                effective_from = $3,
                effective_to = NULL,
                archived_at = NULL,
                updated_at = now()
            FROM policies p
            WHERE pv.id = $1
              AND pv.policy_id = $2
              AND pv.policy_id = p.id
              AND p.tenant_id = $4
              AND p.deleted_at IS NULL
            RETURNING pv.version
            "#,
        )
        .bind(version_pk)
        .bind(policy_id)
        .bind(now)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        if res.is_none() {
            return Err(Status::internal("activate update failed"));
        }

        let _comment = req.activation_comment;
        tx.commit()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let policy = load_policy_view(&self.pool, policy_id, None, tenant_id)
            .await?
            .ok_or_else(|| Status::not_found("policy not found"))?;

        Ok(Response::new(ActivatePolicyResponse {
            policy: Some(policy),
        }))
    }

    async fn deactivate_policy(
        &self,
        request: Request<DeactivatePolicyRequest>,
    ) -> Result<Response<DeactivatePolicyResponse>, Status> {
        let (ctx, tenant_id) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::PolicyWrite)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        let req = request.into_inner();
        let policy_id = parse_uuid(&req.policy_id, "policy_id")?;
        if req.etag.trim().is_empty() {
            return Err(Status::invalid_argument("etag is required"));
        }

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let row: Option<(Uuid, i32)> = sqlx::query_as(
            r#"
            SELECT pv.id, pv.version
            FROM policy_versions pv
            INNER JOIN policies p ON p.id = pv.policy_id
            WHERE pv.policy_id = $1
              AND p.tenant_id = $2
              AND p.deleted_at IS NULL
              AND pv.content_sha256 = $3
              AND pv.status = 'active'
            ORDER BY pv.version DESC
            LIMIT 1
            "#,
        )
        .bind(policy_id)
        .bind(tenant_id)
        .bind(&req.etag)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        let (version_pk, version_no) = row
            .ok_or_else(|| Status::failed_precondition("no active policy version matches etag"))?;

        let now = Utc::now();
        sqlx::query(
            r#"
            UPDATE policy_versions pv
            SET status = 'archived',
                archived_at = $3,
                effective_to = $3,
                updated_at = now()
            FROM policies p
            WHERE pv.id = $1
              AND pv.policy_id = $2
              AND pv.policy_id = p.id
              AND p.tenant_id = $4
              AND p.deleted_at IS NULL
            "#,
        )
        .bind(version_pk)
        .bind(policy_id)
        .bind(now)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        let _comment = req.deactivation_comment;
        tx.commit()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let policy = load_policy_view(&self.pool, policy_id, Some(version_no), tenant_id)
            .await?
            .ok_or_else(|| Status::not_found("policy not found"))?;

        Ok(Response::new(DeactivatePolicyResponse {
            policy: Some(policy),
        }))
    }

    async fn update_policy(
        &self,
        request: Request<UpdatePolicyRequest>,
    ) -> Result<Response<UpdatePolicyResponse>, Status> {
        let (ctx, tenant_id) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::PolicyWrite)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        tracing::warn!(
            method = "UpdatePolicy",
            tenant_id = %tenant_id,
            server_version = env!("CARGO_PKG_VERSION"),
            "unimplemented gRPC method called"
        );
        Err(Status::unimplemented(format!(
            "UpdatePolicy is intentionally deferred (agentfirewall-server {}); no ETA in this release. \
             Use CreatePolicy for a new policy document, or CreatePolicy with create_as_draft=true plus ActivatePolicy to stage a new version workflow until dedicated versioning RPCs ship.",
            env!("CARGO_PKG_VERSION")
        )))
    }

    async fn create_policy_version(
        &self,
        request: Request<CreatePolicyVersionRequest>,
    ) -> Result<Response<CreatePolicyVersionResponse>, Status> {
        let (ctx, tenant_id) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::PolicyWrite)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        tracing::warn!(
            method = "CreatePolicyVersion",
            tenant_id = %tenant_id,
            server_version = env!("CARGO_PKG_VERSION"),
            "unimplemented gRPC method called"
        );
        Err(Status::unimplemented(format!(
            "CreatePolicyVersion is intentionally deferred (agentfirewall-server {}); no ETA in this release. \
             Use CreatePolicy with create_as_draft=true to add a new draft revision, then ActivatePolicy when ready.",
            env!("CARGO_PKG_VERSION")
        )))
    }

    async fn get_policy_version(
        &self,
        request: Request<GetPolicyVersionRequest>,
    ) -> Result<Response<GetPolicyVersionResponse>, Status> {
        let (ctx, tenant_id) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::PolicyRead)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        tracing::warn!(
            method = "GetPolicyVersion",
            tenant_id = %tenant_id,
            server_version = env!("CARGO_PKG_VERSION"),
            "unimplemented gRPC method called"
        );
        Err(Status::unimplemented(format!(
            "GetPolicyVersion is intentionally deferred (agentfirewall-server {}); no ETA in this release. \
             Use GetPolicy with a positive version field to fetch a specific policy revision.",
            env!("CARGO_PKG_VERSION")
        )))
    }

    async fn list_policy_versions(
        &self,
        request: Request<ListPolicyVersionsRequest>,
    ) -> Result<Response<ListPolicyVersionsResponse>, Status> {
        let (ctx, tenant_id) = crate::auth::authenticated_tenant(&request)?;
        crate::auth::require_permission(&ctx, crate::auth::Permission::PolicyRead)
            .map_err(|_| Status::permission_denied("permission denied"))?;
        tracing::warn!(
            method = "ListPolicyVersions",
            tenant_id = %tenant_id,
            server_version = env!("CARGO_PKG_VERSION"),
            "unimplemented gRPC method called"
        );
        Err(Status::unimplemented(format!(
            "ListPolicyVersions is intentionally deferred (agentfirewall-server {}); no ETA in this release. \
             Use ListPolicies together with GetPolicy (version set) to inspect historical revisions until this RPC is available.",
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

fn unique_slug(name: &str) -> String {
    let base: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .chars()
        .take(48)
        .collect();
    let suffix = Uuid::new_v4().simple();
    format!("{base}-{suffix}")
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

fn default_action_to_sql(a: DefaultPolicyAction) -> Result<&'static str, Status> {
    match a {
        DefaultPolicyAction::Allow => Ok("allow"),
        DefaultPolicyAction::Deny => Ok("deny"),
        DefaultPolicyAction::RequireApproval => Ok("require_approval"),
        DefaultPolicyAction::Downgrade => Ok("downgrade"),
        DefaultPolicyAction::Pause => Ok("pause"),
        DefaultPolicyAction::Unspecified => {
            Err(Status::invalid_argument("default_action required"))
        }
    }
}

fn policy_status_to_sql(s: PolicyStatus) -> Result<&'static str, Status> {
    match s {
        PolicyStatus::Draft => Ok("draft"),
        PolicyStatus::Active => Ok("active"),
        PolicyStatus::Archived => Ok("archived"),
        PolicyStatus::Unspecified => Err(Status::invalid_argument("invalid status filter")),
    }
}

fn sql_policy_status(s: &str) -> PolicyStatus {
    match s {
        "draft" => PolicyStatus::Draft,
        "active" => PolicyStatus::Active,
        "archived" => PolicyStatus::Archived,
        _ => PolicyStatus::Unspecified,
    }
}

fn target_type_to_sql(t: RuleTargetType) -> Result<&'static str, Status> {
    match t {
        RuleTargetType::Model => Ok("model"),
        RuleTargetType::Tool => Ok("tool"),
        RuleTargetType::WriteAction => Ok("write_action"),
        RuleTargetType::Delegation => Ok("delegation"),
        RuleTargetType::Budget => Ok("budget"),
        RuleTargetType::Unspecified => Err(Status::invalid_argument("rule.target_type required")),
    }
}

fn rule_action_to_sql(a: RuleAction) -> Result<&'static str, Status> {
    match a {
        RuleAction::Allow => Ok("allow"),
        RuleAction::Deny => Ok("deny"),
        RuleAction::RequireApproval => Ok("require_approval"),
        RuleAction::Downgrade => Ok("downgrade"),
        RuleAction::Pause => Ok("pause"),
        RuleAction::Unspecified => Err(Status::invalid_argument("rule.action required")),
    }
}

fn sql_default_action(s: &str) -> DefaultPolicyAction {
    match s {
        "allow" => DefaultPolicyAction::Allow,
        "deny" => DefaultPolicyAction::Deny,
        "require_approval" => DefaultPolicyAction::RequireApproval,
        "downgrade" => DefaultPolicyAction::Downgrade,
        "pause" => DefaultPolicyAction::Pause,
        _ => DefaultPolicyAction::Unspecified,
    }
}

fn sql_rule_target(s: &str) -> RuleTargetType {
    match s {
        "model" => RuleTargetType::Model,
        "tool" => RuleTargetType::Tool,
        "write_action" => RuleTargetType::WriteAction,
        "delegation" => RuleTargetType::Delegation,
        "budget" => RuleTargetType::Budget,
        _ => RuleTargetType::Unspecified,
    }
}

fn sql_rule_action(s: &str) -> RuleAction {
    match s {
        "allow" => RuleAction::Allow,
        "deny" => RuleAction::Deny,
        "require_approval" => RuleAction::RequireApproval,
        "downgrade" => RuleAction::Downgrade,
        "pause" => RuleAction::Pause,
        _ => RuleAction::Unspecified,
    }
}

fn hash_policy_document(default_action: &str, rules: &[PolicyRule]) -> Result<String, Status> {
    let payload = serde_json::json!({
        "default_action": default_action,
        "rules": rules.iter().map(|r| serde_json::json!({
            "rule_id": r.rule_id,
            "priority": r.priority,
            "target_type": r.target_type,
            "target_selector": r.target_selector,
            "action": r.action,
            "reason_code": r.reason_code,
            "enabled": r.enabled,
        })).collect::<Vec<_>>(),
    });
    let bytes = serde_json::to_vec(&payload).map_err(|e| Status::internal(e.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn struct_to_json(s: &prost_types::Struct) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (k, v) in &s.fields {
        map.insert(k.clone(), prost_value_to_json(v));
    }
    serde_json::Value::Object(map)
}

pub(crate) fn prost_value_to_json(v: &prost_types::Value) -> serde_json::Value {
    use prost_types::value::Kind;
    match v.kind.as_ref() {
        Some(Kind::NullValue(_)) => serde_json::Value::Null,
        Some(Kind::NumberValue(n)) => serde_json::json!(*n),
        Some(Kind::StringValue(s)) => serde_json::Value::String(s.clone()),
        Some(Kind::BoolValue(b)) => serde_json::Value::Bool(*b),
        Some(Kind::StructValue(s)) => struct_to_json(s),
        Some(Kind::ListValue(l)) => {
            serde_json::Value::Array(l.values.iter().map(prost_value_to_json).collect())
        }
        None => serde_json::Value::Null,
    }
}

pub(crate) fn json_to_struct(v: &serde_json::Value) -> prost_types::Struct {
    match v {
        serde_json::Value::Object(map) => {
            let mut fields = BTreeMap::new();
            for (k, val) in map {
                fields.insert(k.clone(), json_to_prost_value(val));
            }
            prost_types::Struct { fields }
        }
        _ => prost_types::Struct::default(),
    }
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
        serde_json::Value::Object(_) => Kind::StructValue(json_to_struct(v)),
    };
    prost_types::Value { kind: Some(kind) }
}

fn decode_cursor(s: &str) -> Result<(DateTime<Utc>, Uuid), Status> {
    let raw = base64_decode(s)?;
    let v: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|_| Status::invalid_argument("invalid cursor"))?;
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
    Ok((dt, uuid))
}

fn encode_cursor(created: DateTime<Utc>, id: Uuid) -> String {
    let v = serde_json::json!({
        "c": created.to_rfc3339(),
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

fn dt_to_ts(dt: DateTime<Utc>) -> Timestamp {
    Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    }
}

async fn load_policy_view(
    pool: &PgPool,
    policy_id: Uuid,
    version: Option<i32>,
    tenant_id: Uuid,
) -> Result<Option<Policy>, Status> {
    let pol: Option<(
        Uuid,
        Uuid,
        String,
        Option<String>,
        DateTime<Utc>,
        DateTime<Utc>,
    )> = sqlx::query_as(
        r#"
        SELECT id, tenant_id, name, description, created_at, updated_at
        FROM policies
        WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
        "#,
    )
    .bind(policy_id)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| Status::internal(e.to_string()))?;

    let Some((pid, tenant_id, name, description, pol_created, _pol_updated)) = pol else {
        return Ok(None);
    };

    let ver: Option<(
        Uuid,
        i32,
        String,
        String,
        String,
        DateTime<Utc>,
        DateTime<Utc>,
    )> = if let Some(vn) = version {
        sqlx::query_as(
            r#"
            SELECT pv.id, pv.version, pv.status, pv.default_action, pv.content_sha256,
                   pv.created_at, pv.updated_at
            FROM policy_versions pv
            INNER JOIN policies p ON p.id = pv.policy_id
            WHERE pv.policy_id = $1 AND p.tenant_id = $2 AND pv.version = $3
            "#,
        )
        .bind(policy_id)
        .bind(tenant_id)
        .bind(vn)
        .fetch_optional(pool)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
    } else {
        sqlx::query_as(
            r#"
            SELECT pv.id, pv.version, pv.status, pv.default_action, pv.content_sha256,
                   pv.created_at, pv.updated_at
            FROM policy_versions pv
            INNER JOIN policies p ON p.id = pv.policy_id
            WHERE pv.policy_id = $1 AND p.tenant_id = $2
            ORDER BY pv.version DESC
            LIMIT 1
            "#,
        )
        .bind(policy_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
    };

    let Some((pv_id, version_no, ver_status, def_action, etag, _ver_created, ver_updated)) = ver
    else {
        return Ok(None);
    };

    let rule_rows: Vec<(
        Uuid,
        String,
        i32,
        bool,
        String,
        Json<serde_json::Value>,
        Json<serde_json::Value>,
        String,
        Json<serde_json::Value>,
        String,
    )> = sqlx::query_as(
        r#"
        SELECT
            id, rule_key, priority, enabled, target_type,
            target_selector, conditions, action, action_config, reason_code
        FROM policy_rules
        WHERE policy_version_id = $1
        ORDER BY priority ASC, id ASC
        "#,
    )
    .bind(pv_id)
    .fetch_all(pool)
    .await
    .map_err(|e| Status::internal(e.to_string()))?;

    let mut rules = Vec::with_capacity(rule_rows.len());
    for (
        _rid,
        rule_key,
        priority,
        enabled,
        target_type,
        target_selector,
        conditions,
        action,
        action_config,
        reason_code,
    ) in rule_rows
    {
        let selector_expr = target_selector
            .0
            .get("expr")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        rules.push(PolicyRule {
            rule_id: rule_key,
            priority,
            target_type: sql_rule_target(&target_type) as i32,
            target_selector: selector_expr,
            conditions: Some(json_to_struct(&conditions.0)),
            action: sql_rule_action(&action) as i32,
            action_config: Some(json_to_struct(&action_config.0)),
            reason_code,
            enabled,
        });
    }

    let labels = Labels {
        entries: Default::default(),
    };

    Ok(Some(Policy {
        policy_id: pid.to_string(),
        version: i64::from(version_no),
        scope_type: ScopeType::Org as i32,
        scope_id: tenant_id.to_string(),
        status: sql_policy_status(&ver_status) as i32,
        default_action: sql_default_action(&def_action) as i32,
        name,
        description: description.unwrap_or_default(),
        rules,
        labels: Some(labels),
        created_by: String::new(),
        created_at: Some(dt_to_ts(pol_created)),
        updated_at: Some(dt_to_ts(ver_updated)),
        etag,
    }))
}

fn map_db_err(e: sqlx::Error, ctx: &'static str) -> Status {
    if let Some(db) = e.as_database_error() {
        if db.code().as_deref() == Some("23505") {
            return Status::already_exists(format!("{ctx}: duplicate key"));
        }
    }
    Status::internal(format!("{ctx}: {e}"))
}
