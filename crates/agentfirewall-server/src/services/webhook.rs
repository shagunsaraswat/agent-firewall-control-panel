use std::time::Duration;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::PgPool;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct WebhookSubscription {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub url: String,
    pub events: Vec<String>,
}

#[derive(Clone)]
pub struct WebhookDispatcher {
    pool: PgPool,
    http: reqwest::Client,
}

impl WebhookDispatcher {
    pub fn new(pool: PgPool, http_client: reqwest::Client) -> Self {
        Self {
            pool,
            http: http_client,
        }
    }

    /// Schedules webhook deliveries; returns immediately without waiting for HTTP callbacks.
    pub async fn dispatch(&self, tenant_id: &str, event_type: &str, payload: serde_json::Value) {
        let tenant = match Uuid::parse_str(tenant_id.trim()) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(error=%e, "webhook dispatch: invalid tenant_id");
                return;
            }
        };

        let pool = self.pool.clone();
        let http = self.http.clone();
        let event = event_type.to_string();
        tokio::spawn(async move {
            let subs = match fetch_matching_subscriptions(&pool, tenant, &event).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error=%e, "webhook dispatch: load subscriptions failed");
                    return;
                }
            };

            let body = match serde_json::to_vec(&payload) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(error=%e, "webhook dispatch: serialize payload failed");
                    return;
                }
            };

            for sub in subs {
                let http = http.clone();
                let event = event.clone();
                let body = body.clone();
                tokio::spawn(async move {
                    deliver_subscription(&http, sub, &event, &body).await;
                });
            }
        });
    }
}

struct SubscriptionDelivery {
    _id: Uuid,
    url: String,
    secret: Vec<u8>,
}

async fn fetch_matching_subscriptions(
    pool: &PgPool,
    tenant_id: Uuid,
    event_type: &str,
) -> Result<Vec<SubscriptionDelivery>, sqlx::Error> {
    let rows: Vec<(Uuid, String, Vec<u8>)> = sqlx::query_as(
        r#"
        SELECT id, url, secret_hmac_sha256
        FROM webhook_subscriptions
        WHERE tenant_id = $1
          AND status = 'active'
          AND ($2::text = ANY(events))
        "#,
    )
    .bind(tenant_id)
    .bind(event_type)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(id, url, secret)| SubscriptionDelivery {
            _id: id,
            url,
            secret,
        })
        .collect())
}

async fn deliver_subscription(
    http: &reqwest::Client,
    sub: SubscriptionDelivery,
    event_type: &str,
    body: &[u8],
) {
    let delivery_id = Uuid::new_v4();
    let sig = compute_hmac_hex(&sub.secret, body);
    let mut attempt = 0u32;
    let mut backoff = Duration::from_secs(1);

    loop {
        let res = http
            .post(&sub.url)
            .header("Content-Type", "application/json")
            .header("X-AgentFirewall-Signature", format!("sha256={sig}"))
            .header("X-AgentFirewall-Event", event_type)
            .header("X-AgentFirewall-Delivery", delivery_id.to_string())
            .body(body.to_vec())
            .send()
            .await;

        match res {
            Ok(r) if r.status().is_success() => return,
            Ok(r) => {
                tracing::warn!(
                    status = %r.status(),
                    url = %sub.url,
                    attempt,
                    "webhook delivery non-success status"
                );
            }
            Err(e) => {
                tracing::warn!(error=%e, url=%sub.url, attempt, "webhook delivery request error");
            }
        }

        attempt += 1;
        if attempt >= 3 {
            break;
        }
        tokio::time::sleep(backoff).await;
        backoff = backoff.saturating_mul(2);
    }
}

/// HMAC-SHA256 over the raw JSON body; returns lowercase hex (without `sha256=` prefix).
pub(crate) fn compute_hmac_hex(secret: &[u8], body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts arbitrary key lengths");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

pub async fn create_subscription(
    pool: &PgPool,
    tenant_id: &str,
    url: &str,
    events: &[String],
    secret: &str,
) -> Result<Uuid, sqlx::Error> {
    let tid = Uuid::parse_str(tenant_id.trim()).map_err(|e| {
        sqlx::Error::Decode(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            e.to_string(),
        )))
    })?;
    if events.is_empty() {
        return Err(sqlx::Error::Decode(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "events must not be empty",
        ))));
    }
    let id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO webhook_subscriptions (id, tenant_id, url, events, secret_hmac_sha256, status)
        VALUES ($1, $2, $3, $4, $5, 'active')
        "#,
    )
    .bind(id)
    .bind(tid)
    .bind(url)
    .bind(events)
    .bind(secret.as_bytes())
    .execute(pool)
    .await?;
    Ok(id)
}

pub async fn list_subscriptions(
    pool: &PgPool,
    tenant_id: &str,
) -> Result<Vec<WebhookSubscription>, sqlx::Error> {
    let tid = Uuid::parse_str(tenant_id.trim()).map_err(|e| {
        sqlx::Error::Decode(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            e.to_string(),
        )))
    })?;
    let rows: Vec<(Uuid, Uuid, String, Vec<String>)> = sqlx::query_as(
        r#"
        SELECT id, tenant_id, url, events
        FROM webhook_subscriptions
        WHERE tenant_id = $1 AND status <> 'disabled'
        ORDER BY created_at DESC
        "#,
    )
    .bind(tid)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(id, tenant_id, url, events)| WebhookSubscription {
            id,
            tenant_id,
            url,
            events,
        })
        .collect())
}

pub async fn delete_subscription(pool: &PgPool, id: Uuid) -> Result<u64, sqlx::Error> {
    let r = sqlx::query("DELETE FROM webhook_subscriptions WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_signature_matches_rfc_example_vector() {
        let secret = b"secret";
        let body = br#"{"hello":"world"}"#;
        let sig = compute_hmac_hex(secret, body);
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(body);
        let expected = hex::encode(mac.finalize().into_bytes());
        assert_eq!(sig, expected);
        assert_eq!(sig.len(), 64);
    }
}
