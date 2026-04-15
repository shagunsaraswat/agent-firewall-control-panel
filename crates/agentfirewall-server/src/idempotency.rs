use axum::http::HeaderMap;
use base64::Engine;
use chrono::{Duration, Utc};
use prost::Message;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tonic::Status;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdempotencyRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub operation: String,
    pub idempotency_key: String,
    pub status: String,
    pub response_status_code: Option<i32>,
    pub response_body: Option<serde_json::Value>,
}

#[derive(Debug)]
pub enum IdempotencyCheck {
    /// No prior record — proceed with the operation
    New,
    /// Prior record exists and is complete — return the cached response
    Replay(IdempotencyRecord),
    /// Prior record exists but is still processing — reject as conflict
    InProgress,
}

/// Check if an idempotency key has been seen before.
///
/// Uses a single statement: `INSERT ... ON CONFLICT DO NOTHING` plus a follow-up
/// read of the existing row when the insert did not occur, so the decision is atomic.
pub async fn check(
    pool: &PgPool,
    tenant_id: Uuid,
    operation: &str,
    key: &str,
    ttl_secs: u64,
) -> Result<IdempotencyCheck, sqlx::Error> {
    let expires_at = Utc::now() + Duration::seconds(ttl_secs as i64);

    let (id, status, resp_code, resp_body, is_insert): (
        Uuid,
        String,
        Option<i32>,
        Option<serde_json::Value>,
        bool,
    ) = sqlx::query_as(
        r#"
        WITH inserted AS (
            INSERT INTO idempotency_keys (tenant_id, operation, idempotency_key, status, expires_at)
            VALUES ($1, $2, $3, 'processing', $4)
            ON CONFLICT (tenant_id, operation, idempotency_key) DO NOTHING
            RETURNING id, status, response_status_code, response_body, TRUE AS is_insert
        )
        SELECT id, status, response_status_code, response_body, TRUE AS is_insert FROM inserted
        UNION ALL
        SELECT k.id, k.status, k.response_status_code, k.response_body, FALSE AS is_insert
        FROM idempotency_keys k
        WHERE k.tenant_id = $1
          AND k.operation = $2
          AND k.idempotency_key = $3
          AND NOT EXISTS (SELECT 1 FROM inserted)
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(operation)
    .bind(key)
    .bind(expires_at)
    .fetch_one(pool)
    .await?;

    match status.as_str() {
        "completed" => Ok(IdempotencyCheck::Replay(IdempotencyRecord {
            id,
            tenant_id,
            operation: operation.to_string(),
            idempotency_key: key.to_string(),
            status,
            response_status_code: resp_code,
            response_body: resp_body,
        })),
        "processing" if is_insert => Ok(IdempotencyCheck::New),
        "processing" => Ok(IdempotencyCheck::InProgress),
        _ => Ok(IdempotencyCheck::New),
    }
}

/// Mark an idempotency key as completed with a response.
pub async fn complete(
    pool: &PgPool,
    tenant_id: Uuid,
    operation: &str,
    key: &str,
    status_code: i32,
    response_body: &serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE idempotency_keys
        SET status = 'completed',
            response_status_code = $4,
            response_body = $5
        WHERE tenant_id = $1 AND operation = $2 AND idempotency_key = $3
        "#,
    )
    .bind(tenant_id)
    .bind(operation)
    .bind(key)
    .bind(status_code)
    .bind(response_body)
    .execute(pool)
    .await?;
    Ok(())
}

/// Clean up expired idempotency keys.
pub async fn cleanup_expired(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM idempotency_keys WHERE expires_at < now()")
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// Extract idempotency key from gRPC metadata or REST header.
pub fn extract_key_grpc(metadata: &tonic::metadata::MetadataMap) -> Option<String> {
    metadata
        .get("x-idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
}

pub fn extract_key_rest(headers: &HeaderMap) -> Option<String> {
    headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
}

/// Store a protobuf response in JSON (`jsonb`) for idempotent replay.
pub fn encode_proto_response<M: Message>(msg: &M) -> serde_json::Value {
    let bytes = msg.encode_to_vec();
    serde_json::json!({
        "protobuf": base64::engine::general_purpose::STANDARD.encode(bytes)
    })
}

/// Decode a cached protobuf response produced by [`encode_proto_response`].
pub fn decode_proto_response<M: Message + Default>(v: &serde_json::Value) -> Result<M, Status> {
    let b64 = v
        .get("protobuf")
        .and_then(|x| x.as_str())
        .ok_or_else(|| Status::internal("idempotency replay: missing protobuf payload"))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|_| Status::internal("idempotency replay: invalid base64"))?;
    M::decode(&*bytes).map_err(|_| Status::internal("idempotency replay: invalid protobuf"))
}
