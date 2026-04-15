//! Cross-tenant isolation and authorization integration tests.
//!
//! **Infrastructure**: Start dependencies with [`agentfirewall_integration_tests::harness::compose_up`]
//! (or `docker compose -f docker/docker-compose.yml up -d`), run migrations, then start
//! `agentfirewall-server` with at least two tenants and API keys scoped per tenant. Tests assume
//! distinct credentials for tenant A and tenant B and optionally a key with intentionally reduced
//! permissions.
//!
//! Environment overrides (defaults match common local fixtures):
//! - `AGENTVAULT_TEST_KEY_TENANT_A`, `AGENTVAULT_TEST_KEY_TENANT_B`, `AGENTVAULT_TEST_KEY_POLICY_READ_ONLY`
//! - `AGENTVAULT_TEST_TENANT_A_ID`, `AGENTVAULT_TEST_TENANT_B_ID` (must match `api_keys.tenant_id` for each key)
//!
//! Run ignored tests explicitly:
//! `cargo test -p agentfirewall-integration-tests --test tenant_isolation -- --ignored`

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
        "description": "integration tenant isolation",
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

async fn post_json(
    client: &Client,
    base: &str,
    api_key: &str,
    path: &str,
    body: &Value,
) -> reqwest::Response {
    client
        .post(format!("{base}{path}"))
        .header("Authorization", format!("Bearer {api_key}"))
        .header("Content-Type", "application/json")
        .json(body)
        .send()
        .await
        .unwrap_or_else(|e| panic!("POST {path} failed: {e}"))
}

/// **Expected flow**
///
/// 1. Create or seed a policy owned by tenant B (via admin/fixture).
/// 2. Using tenant A's API key, call policy list and get-by-id endpoints that would expose B's policy.
/// 3. Assert empty list, 404, or equivalent — responses must never include tenant B's policy body or id.
#[tokio::test]
#[ignore = "requires Docker Compose stack, migrated DB, and running agentfirewall-server with multi-tenant fixtures"]
async fn tenant_a_cannot_read_tenant_b_policies() {
    tokio::time::sleep(Duration::ZERO).await;
    let harness = TestHarness {
        grpc_addr: "127.0.0.1:50051".parse().unwrap(),
        http_addr: "127.0.0.1:8080".parse().unwrap(),
    };
    let _ = harness::check_compose_running().await;

    let base = format!("http://{}", harness.http_addr);
    let key_a = env_or("AGENTVAULT_TEST_KEY_TENANT_A", "test-api-key-tenant-a");
    let key_b = env_or("AGENTVAULT_TEST_KEY_TENANT_B", "test-api-key-tenant-b");
    let tenant_b = env_or(
        "AGENTVAULT_TEST_TENANT_B_ID",
        "22222222-2222-4222-8222-222222222222",
    );

    let client = Client::new();
    let name = format!("iso-policy-{}", Uuid::new_v4());
    let create = post_json(
        &client,
        &base,
        &key_b,
        "/v1/policies",
        &policy_body(&tenant_b, &name),
    )
    .await;
    assert_eq!(
        create.status(),
        reqwest::StatusCode::CREATED,
        "tenant B should create policy: {}",
        create.text().await.unwrap_or_default()
    );
    let created: Value = create.json().await.expect("create policy json");
    let policy_id = created["policy"]["policyId"]
        .as_str()
        .expect("policyId")
        .to_string();

    let get_a = client
        .get(format!("{base}/v1/policies/{policy_id}"))
        .header("Authorization", format!("Bearer {key_a}"))
        .send()
        .await
        .expect("GET policy");
    let status = get_a.status();
    assert!(
        status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::FORBIDDEN,
        "tenant A must not read tenant B policy; got {status}"
    );
}

/// **Expected flow**
///
/// 1. Create a run for tenant B.
/// 2. As tenant A, attempt PATCH/POST on that run id (status transitions, step updates, etc.).
/// 3. Assert 403/404 — mutation must not apply to another tenant's run.
#[tokio::test]
#[ignore = "requires Docker Compose stack, migrated DB, and running agentfirewall-server with multi-tenant fixtures"]
async fn tenant_a_cannot_modify_tenant_b_runs() {
    tokio::time::sleep(Duration::ZERO).await;
    let harness = TestHarness {
        grpc_addr: "127.0.0.1:50051".parse().unwrap(),
        http_addr: "127.0.0.1:8080".parse().unwrap(),
    };
    let _ = harness::check_compose_running().await;

    let base = format!("http://{}", harness.http_addr);
    let key_a = env_or("AGENTVAULT_TEST_KEY_TENANT_A", "test-api-key-tenant-a");
    let key_b = env_or("AGENTVAULT_TEST_KEY_TENANT_B", "test-api-key-tenant-b");
    let tenant_b = env_or(
        "AGENTVAULT_TEST_TENANT_B_ID",
        "22222222-2222-4222-8222-222222222222",
    );
    let agent_id = Uuid::new_v4().to_string();

    let client = Client::new();
    let run_body = json!({
        "scope": { "scopeType": "ORG", "scopeId": tenant_b },
        "agentId": agent_id,
        "goal": "tenant-isolation-run"
    });
    let create = post_json(&client, &base, &key_b, "/v1/runs", &run_body).await;
    assert_eq!(
        create.status(),
        reqwest::StatusCode::CREATED,
        "tenant B should create run: {}",
        create.text().await.unwrap_or_default()
    );
    let run_json: Value = create.json().await.expect("run json");
    let run_id = run_json["runId"].as_str().expect("runId").to_string();

    let cancel = client
        .post(format!("{base}/v1/runs/{run_id}/cancel"))
        .header("Authorization", format!("Bearer {key_a}"))
        .header("Content-Type", "application/json")
        .json(&json!({ "reasonCode": "test", "comment": "cross-tenant cancel" }))
        .send()
        .await
        .expect("cancel run");
    let status = cancel.status();
    assert!(
        !status.is_success(),
        "tenant A must not cancel tenant B run; unexpected success"
    );
    assert!(
        status == reqwest::StatusCode::NOT_FOUND
            || status == reqwest::StatusCode::FORBIDDEN
            || status == reqwest::StatusCode::PRECONDITION_FAILED,
        "expected failed cancel for wrong tenant, got {status}"
    );
}

/// **Expected flow**
///
/// 1. Use an API key that is valid but lacks a required permission (e.g. read-only key for a mutating route).
/// 2. Issue the protected request.
/// 3. Assert HTTP 403 and gRPC `PermissionDenied` (or documented equivalent) with stable error shape.
#[tokio::test]
#[ignore = "requires Docker Compose stack and API keys with granular permission matrices"]
async fn api_key_without_required_permission_gets_403() {
    tokio::time::sleep(Duration::ZERO).await;
    let harness = TestHarness {
        grpc_addr: "127.0.0.1:50051".parse().unwrap(),
        http_addr: "127.0.0.1:8080".parse().unwrap(),
    };
    let _ = harness::check_compose_running().await;

    let base = format!("http://{}", harness.http_addr);
    let read_only_key = env_or(
        "AGENTVAULT_TEST_KEY_POLICY_READ_ONLY",
        "test-api-key-policy-readonly",
    );
    let tenant_a = env_or(
        "AGENTVAULT_TEST_TENANT_A_ID",
        "11111111-1111-4111-8111-111111111111",
    );

    let client = Client::new();
    let resp = post_json(
        &client,
        &base,
        &read_only_key,
        "/v1/policies",
        &policy_body(
            &tenant_a,
            &format!("rw-denied-{}", Uuid::new_v4()),
        ),
    )
    .await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "policy create without PolicyWrite should be 403: {}",
        resp.text().await.unwrap_or_default()
    );

    use agentfirewall_server::proto::common_v1::{ResourceScope, ScopeType};
    use agentfirewall_server::proto::policy_v1::policy_service_client::PolicyServiceClient;
    use agentfirewall_server::proto::policy_v1::{
        CreatePolicyRequest, DefaultPolicyAction, PolicyRule, RuleAction, RuleTargetType,
    };
    use tonic::metadata::AsciiMetadataValue;

    let channel = tonic::transport::Endpoint::from_shared(format!("http://{}", harness.grpc_addr))
        .expect("grpc endpoint")
        .connect()
        .await
        .expect("grpc connect");

    let mut grpc = PolicyServiceClient::new(channel);
    let rule = PolicyRule {
        rule_id: Uuid::new_v4().to_string(),
        priority: 0,
        target_type: RuleTargetType::Tool as i32,
        target_selector: "*".into(),
        conditions: None,
        action: RuleAction::Allow as i32,
        action_config: None,
        reason_code: String::new(),
        enabled: true,
    };
    let mut req = tonic::Request::new(CreatePolicyRequest {
        idempotency: None,
        scope: Some(ResourceScope {
            scope_type: ScopeType::Org as i32,
            scope_id: tenant_a.clone(),
        }),
        name: "grpc-permission-test".into(),
        description: String::new(),
        default_action: DefaultPolicyAction::Allow as i32,
        rules: vec![rule],
        labels: None,
        create_as_draft: true,
    });
    let meta_val = AsciiMetadataValue::try_from(read_only_key.as_str()).expect("ascii api key");
    req.metadata_mut().insert("x-api-key", meta_val);

    let err = grpc
        .create_policy(req)
        .await
        .expect_err("create_policy should fail without PolicyWrite");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}
