use serde::Serialize;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub tenant_id: String,
    pub actor: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub detail: serde_json::Value,
    pub ip_address: Option<String>,
}

#[derive(Debug, Serialize)]
struct AuditMetadataEnvelope {
    #[serde(flatten)]
    pub detail: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
}

pub struct AuditLogger;

fn decode_err(msg: impl Into<String>) -> sqlx::Error {
    sqlx::Error::Decode(Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        msg.into(),
    )))
}

impl AuditLogger {
    pub async fn log(pool: &PgPool, entry: AuditEntry) -> Result<(), sqlx::Error> {
        let tenant =
            Uuid::parse_str(entry.tenant_id.trim()).map_err(|e| decode_err(e.to_string()))?;

        let (actor_id, actor_type) = parse_actor(&entry.actor);
        let resource_id = if entry.resource_id.trim().is_empty() {
            None
        } else {
            Some(Uuid::parse_str(entry.resource_id.trim()).map_err(|e| decode_err(e.to_string()))?)
        };

        let client_ip = entry
            .ip_address
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let metadata = json!(AuditMetadataEnvelope {
            detail: entry.detail,
            client_ip: client_ip.clone(),
        });

        let id = Uuid::now_v7();

        sqlx::query(
            r#"
            INSERT INTO audit_log (
                id, tenant_id, actor_id, actor_type, action, resource_type, resource_id,
                request_id, outcome, metadata, ip_inet, user_agent, recorded_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, 'success', $8, $9, NULL, now())
            "#,
        )
        .bind(id)
        .bind(tenant)
        .bind(actor_id)
        .bind(actor_type)
        .bind(&entry.action)
        .bind(&entry.resource_type)
        .bind(resource_id)
        .bind(metadata)
        .bind(client_ip)
        .execute(pool)
        .await?;

        Ok(())
    }
}

fn parse_actor(actor: &str) -> (Option<Uuid>, &'static str) {
    let t = actor.trim();
    if t.eq_ignore_ascii_case("system") {
        return (None, "system");
    }
    if let Ok(u) = Uuid::parse_str(t) {
        return (Some(u), "user");
    }
    (None, "user")
}

/// Maps an [`AuditEntry`] to insert parameters for tests / validation (no DB).
#[cfg(test)]
fn audit_row_preview(entry: &AuditEntry) -> Result<AuditRowPreview, String> {
    let tenant = Uuid::parse_str(entry.tenant_id.trim()).map_err(|e| e.to_string())?;
    let (actor_id, actor_type) = parse_actor(&entry.actor);
    let resource_id = if entry.resource_id.trim().is_empty() {
        None
    } else {
        Some(Uuid::parse_str(entry.resource_id.trim()).map_err(|e| e.to_string())?)
    };
    Ok(AuditRowPreview {
        tenant_id: tenant,
        actor_id,
        actor_type: actor_type.to_string(),
        action: entry.action.clone(),
        resource_type: entry.resource_type.clone(),
        resource_id,
        outcome: "success".to_string(),
    })
}

#[derive(Debug, PartialEq, Eq)]
#[cfg(test)]
struct AuditRowPreview {
    pub tenant_id: Uuid,
    pub actor_id: Option<Uuid>,
    pub actor_type: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<Uuid>,
    pub outcome: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_entry_preview_system_actor() {
        let entry = AuditEntry {
            tenant_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            actor: "system".into(),
            action: "approval.resolved".into(),
            resource_type: "approval".into(),
            resource_id: "6ba7b810-9dad-11d1-80b4-00c04fd430c8".into(),
            detail: json!({"k": 1}),
            ip_address: Some("192.0.2.1".into()),
        };
        let p = audit_row_preview(&entry).unwrap();
        assert_eq!(p.actor_type, "system");
        assert!(p.actor_id.is_none());
        assert_eq!(p.outcome, "success");
    }

    #[test]
    fn audit_entry_preview_uuid_actor() {
        let aid = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
        let entry = AuditEntry {
            tenant_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            actor: aid.into(),
            action: "incident.created".into(),
            resource_type: "incident".into(),
            resource_id: "".into(),
            detail: json!({}),
            ip_address: None,
        };
        let p = audit_row_preview(&entry).unwrap();
        assert_eq!(p.actor_type, "user");
        assert_eq!(p.actor_id, Some(Uuid::parse_str(aid).unwrap()));
        assert!(p.resource_id.is_none());
    }
}
