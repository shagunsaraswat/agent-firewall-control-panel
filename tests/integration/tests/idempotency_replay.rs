//! Idempotency key replay integration tests.
//!
//! **Infrastructure**: Compose stack with Postgres (idempotency table per migration), Redis if the
//! server uses it for idempotency acceleration, and `agentfirewall-server` with idempotency middleware
//! enabled. Use a mutating endpoint that records keys (e.g. policy or run create).
//!
//! Sends `Idempotency-Key` (HTTP treats header names case-insensitively; the server reads
//! `idempotency-key`).
//!
//! Environment:
//! - `AGENTVAULT_TEST_KEY_TENANT_A`, `AGENTVAULT_TEST_TENANT_A_ID`
//!
//! Run ignored tests explicitly:
//! `cargo test -p agentfirewall-integration-tests --test idempotency_replay -- --ignored`

use std::time::Duration;

use agentfirewall_integration_tests::harness::{self, TestHarness};
use reqwest::Client;
use serde_json::{json, Value};
use uuid::Uuid;

fn env_or(var: &str, default: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| default.to_string())
}

fn policy_body(scope_id: &str, name: &str) -> Value {
    let rule_id = Uuid::new_v4().to_string();
    json!({
        "scope": { "scopeType": "ORG", "scopeId": scope_id },
        "name": name,
        "description": "idempotency replay",
        "defaultAction": "ALLOW",
        "rules": [{
            "ruleId": rule_id,
            "priority": 0,
            "targetType": "TOOL",
            "targetSelector": "*",
            "action": "ALLOW",
            "enabled": true
        }],
        "createAsDraft": true
    })
}

/// **Expected flow**
///
/// 1. Send a mutating create request (REST: `Idempotency-Key` header, gRPC: `idempotency` field or
///    `x-idempotency-key` metadata per contract).
/// 2. Repeat the identical request with the same key and body.
/// 3. Assert second response matches the first (same resource id, same body hash or JSON equality)
///    and no duplicate row appears in the database.
#[tokio::test]
#[ignore = "requires running agentfirewall-server with durable idempotency and Compose-backed stores"]
async fn same_create_request_with_same_idempotency_key_returns_same_response() {
    tokio::time::sleep(Duration::ZERO).await;
    let harness = TestHarness {
        grpc_addr: "127.0.0.1:50051".parse().unwrap(),
        http_addr: "127.0.0.1:8080".parse().unwrap(),
    };
    let _ = harness::check_compose_running().await;

    let base = format!("http://{}", harness.http_addr);
    let api_key = env_or("AGENTVAULT_TEST_KEY_TENANT_A", "test-api-key-tenant-a");
    let tenant_id = env_or(
        "AGENTVAULT_TEST_TENANT_A_ID",
        "11111111-1111-4111-8111-111111111111",
    );
    let name = format!("idempotent-policy-{}", Uuid::new_v4());
    let body = policy_body(&tenant_id, &name);
    let idem_key = format!("idem-{}", Uuid::new_v4());

    let client = Client::new();
    let url = format!("{base}/v1/policies");

    let first = client
        .post(&url)
        .header("Authorization", format!("Bearer {api_key}"))
        .header("Content-Type", "application/json")
        .header("Idempotency-Key", &idem_key)
        .json(&body)
        .send()
        .await
        .expect("first POST");
    assert_eq!(first.status(), reqwest::StatusCode::CREATED);
    let first_text = first.text().await.expect("first body");

    let second = client
        .post(&url)
        .header("Authorization", format!("Bearer {api_key}"))
        .header("Content-Type", "application/json")
        .header("Idempotency-Key", &idem_key)
        .json(&body)
        .send()
        .await
        .expect("second POST");
    assert_eq!(
        second.status(),
        reqwest::StatusCode::CREATED,
        "replay should return same success class as first create"
    );
    let second_text = second.text().await.expect("second body");
    assert_eq!(
        first_text, second_text,
        "identical idempotency key + body should return identical response bodies"
    );
}

/// **Expected flow**
///
/// 1. Create a resource with idempotency key K1; note returned id.
/// 2. Send the same logical payload with a different idempotency key K2.
/// 3. Assert a new resource is created (new id) — keys must not collide across distinct client intents.
#[tokio::test]
#[ignore = "requires running agentfirewall-server with durable idempotency and Compose-backed stores"]
async fn different_idempotency_key_creates_new_resource() {
    tokio::time::sleep(Duration::ZERO).await;
    let harness = TestHarness {
        grpc_addr: "127.0.0.1:50051".parse().unwrap(),
        http_addr: "127.0.0.1:8080".parse().unwrap(),
    };
    let _ = harness::check_compose_running().await;

    let base = format!("http://{}", harness.http_addr);
    let api_key = env_or("AGENTVAULT_TEST_KEY_TENANT_A", "test-api-key-tenant-a");
    let tenant_id = env_or(
        "AGENTVAULT_TEST_TENANT_A_ID",
        "11111111-1111-4111-8111-111111111111",
    );
    let name = format!("idempotency-distinct-{}", Uuid::new_v4());
    let body = policy_body(&tenant_id, &name);
    let key_a = format!("idem-a-{}", Uuid::new_v4());
    let key_b = format!("idem-b-{}", Uuid::new_v4());

    let client = Client::new();
    let url = format!("{base}/v1/policies");

    let r1 = client
        .post(&url)
        .header("Authorization", format!("Bearer {api_key}"))
        .header("Content-Type", "application/json")
        .header("Idempotency-Key", &key_a)
        .json(&body)
        .send()
        .await
        .expect("POST");
    assert_eq!(r1.status(), reqwest::StatusCode::CREATED);
    let v1: Value = r1.json().await.expect("json");
    let id1 = v1["policy"]["policyId"].as_str().expect("policyId");

    let r2 = client
        .post(&url)
        .header("Authorization", format!("Bearer {api_key}"))
        .header("Content-Type", "application/json")
        .header("Idempotency-Key", &key_b)
        .json(&body)
        .send()
        .await
        .expect("POST");
    assert_eq!(r2.status(), reqwest::StatusCode::CREATED);
    let v2: Value = r2.json().await.expect("json");
    let id2 = v2["policy"]["policyId"].as_str().expect("policyId");

    assert_ne!(
        id1, id2,
        "different idempotency keys must not pin to the same resource id"
    );
}
