use chrono::Utc;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use super::types::{parse_permissions, AuthContext, AuthError, Permission, PrincipalType};

/// Validates API keys using the `api_keys` table (SHA-256 at rest).
#[derive(Clone)]
pub struct ApiKeyAuth {
    pool: PgPool,
}

#[derive(sqlx::FromRow)]
struct ApiKeyRow {
    id: Uuid,
    tenant_id: String,
    permissions: Vec<String>,
    revoked_at: Option<chrono::DateTime<Utc>>,
    expires_at: Option<chrono::DateTime<Utc>>,
    key_hash: Vec<u8>,
}

impl ApiKeyAuth {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Hash raw key material with SHA-256 (32 bytes).
    pub fn hash_key(key: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        hasher.finalize().into()
    }

    /// Load and validate a key; on success returns [`AuthContext`].
    pub async fn validate(&self, key: &str) -> Result<AuthContext, AuthError> {
        let trimmed = key.trim();
        if trimmed.is_empty() {
            return Err(AuthError::InvalidKey);
        }

        let computed = Self::hash_key(trimmed);

        let row = sqlx::query_as::<_, ApiKeyRow>(
            r#"
            SELECT id, tenant_id, permissions, revoked_at, expires_at, key_hash
            FROM api_keys
            WHERE key_hash = $1
            LIMIT 1
            "#,
        )
        .bind(&computed[..])
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        let Some(row) = row else {
            // Normalize verification work: still compare against a zero digest (same length).
            let _ = computed.ct_eq(&[0u8; 32]);
            return Err(AuthError::InvalidKey);
        };

        if computed
            .as_slice()
            .ct_eq(row.key_hash.as_slice())
            .unwrap_u8()
            != 1
        {
            return Err(AuthError::InvalidKey);
        }

        if row.revoked_at.is_some() {
            return Err(AuthError::KeyRevoked);
        }

        if let Some(exp) = row.expires_at {
            if exp < Utc::now() {
                return Err(AuthError::KeyExpired);
            }
        }

        let permissions: std::collections::HashSet<Permission> =
            parse_permissions(&row.permissions);

        Ok(AuthContext {
            tenant_id: row.tenant_id,
            principal_id: row.id.to_string(),
            principal_type: PrincipalType::ApiKey,
            permissions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    async fn test_pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .ok()
    }

    #[tokio::test]
    async fn validate_accepts_active_key() {
        let Some(pool) = test_pool().await else {
            eprintln!("skip validate_accepts_active_key: DATABASE_URL not set");
            return;
        };

        sqlx::migrate!("../../migrations/postgres")
            .run(&pool)
            .await
            .expect("migrate");

        let tenant = Uuid::new_v4().to_string();
        let raw_key = format!("av_test_{}", Uuid::new_v4());
        let hash = ApiKeyAuth::hash_key(&raw_key);
        let prefix: String = raw_key.chars().take(8).collect();

        sqlx::query(
            r#"
            INSERT INTO api_keys (tenant_id, name, key_hash, key_prefix, permissions)
            VALUES ($1, 'test', $2, $3, ARRAY['PolicyRead']::text[])
            "#,
        )
        .bind(&tenant)
        .bind(&hash[..])
        .bind(&prefix)
        .execute(&pool)
        .await
        .expect("insert key");

        let auth = ApiKeyAuth::new(pool.clone());
        let ctx = auth.validate(&raw_key).await.expect("valid");
        assert_eq!(ctx.tenant_id, tenant);
        assert_eq!(ctx.principal_type, PrincipalType::ApiKey);
        assert!(ctx.permissions.contains(&Permission::PolicyRead));

        sqlx::query("DELETE FROM api_keys WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .ok();
    }

    #[tokio::test]
    async fn validate_rejects_unknown_key() {
        let Some(pool) = test_pool().await else {
            eprintln!("skip validate_rejects_unknown_key: DATABASE_URL not set");
            return;
        };

        sqlx::migrate!("../../migrations/postgres")
            .run(&pool)
            .await
            .expect("migrate");

        let auth = ApiKeyAuth::new(pool);
        let err = auth
            .validate("av_test_no_such_key_xxxxxxxx")
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::InvalidKey));
    }

    #[tokio::test]
    async fn validate_rejects_revoked_key() {
        let Some(pool) = test_pool().await else {
            eprintln!("skip validate_rejects_revoked_key: DATABASE_URL not set");
            return;
        };

        sqlx::migrate!("../../migrations/postgres")
            .run(&pool)
            .await
            .expect("migrate");

        let tenant = Uuid::new_v4().to_string();
        let raw_key = format!("av_test_{}", Uuid::new_v4());
        let hash = ApiKeyAuth::hash_key(&raw_key);
        let prefix: String = raw_key.chars().take(8).collect();

        sqlx::query(
            r#"
            INSERT INTO api_keys (tenant_id, name, key_hash, key_prefix, permissions, revoked_at)
            VALUES ($1, 'revoked', $2, $3, ARRAY[]::text[], now())
            "#,
        )
        .bind(&tenant)
        .bind(&hash[..])
        .bind(&prefix)
        .execute(&pool)
        .await
        .expect("insert");

        let auth = ApiKeyAuth::new(pool.clone());
        let err = auth.validate(&raw_key).await.unwrap_err();
        assert!(matches!(err, AuthError::KeyRevoked));

        sqlx::query("DELETE FROM api_keys WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .ok();
    }
}
