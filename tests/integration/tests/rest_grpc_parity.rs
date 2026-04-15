//! REST and gRPC response parity integration tests.
//!
//! **Infrastructure**: Same as other integration tests: Compose-backed Postgres/Redis/NATS (and
//! optional ClickHouse), migrations applied, `agentfirewall-server` listening on configured HTTP and gRPC
//! addresses. Clients must send equivalent auth headers/metadata and payloads.
//!
//! Environment:
//! - `AGENTVAULT_TEST_KEY_TENANT_A` (default `test-api-key-tenant-a`)
//! - `AGENTVAULT_TEST_TENANT_A_ID` (default `11111111-1111-4111-8111-111111111111`)
//!
//! Run ignored tests explicitly:
//! `cargo test -p agentfirewall-integration-tests --test rest_grpc_parity -- --ignored`

use std::time::Duration;

use agentfirewall_integration_tests::harness::{self, TestHarness};
use agentfirewall_server::proto::common_v1::{ResourceScope, ScopeType};
use agentfirewall_server::proto::policy_v1::policy_service_client::PolicyServiceClient;
use agentfirewall_server::proto::policy_v1::{
    CreatePolicyRequest, DefaultPolicyAction, PolicyRule, RuleAction, RuleTargetType,
};
use reqwest::Client;
use serde_json::{json, Value};
use tonic::metadata::AsciiMetadataValue;
use uuid::Uuid;

fn env_or(var: &str, default: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| default.to_string())
}

fn policy_json(scope_id: &str, name: &str) -> Value {
    let rule_id = Uuid::new_v4().to_string();
    json!({
        "scope": { "scopeType": "ORG", "scopeId": scope_id },
        "name": name,
        "description": "rest-grpc parity",
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

fn comparable_policy_fields(p: &Value) -> (String, String, String, String, String, usize) {
    let pol = &p["policy"];
    (
        pol["name"].as_str().unwrap_or("").to_string(),
        pol["version"].to_string(),
        pol["status"].as_str().unwrap_or("").to_string(),
        pol["defaultAction"].as_str().unwrap_or("").to_string(),
        pol["scopeType"].as_str().unwrap_or("").to_string(),
        pol["rules"].as_array().map(|a| a.len()).unwrap_or(0),
    )
}

/// **Expected flow**
///
/// 1. Define a minimal policy create payload (name, rules blob, tenant context).
/// 2. POST `/v1/...` policy create with `TestClient` and capture JSON body + status.
/// 3. Call the matching gRPC `CreatePolicy` (or equivalent) with the same logical fields.
/// 4. Assert resource ids match, canonical fields match, and success/failure agree (e.g. both 201/OK or both validation errors).
#[tokio::test]
#[ignore = "requires running agentfirewall-server with REST and gRPC enabled"]
async fn creating_policy_via_rest_and_grpc_produces_equivalent_responses() {
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
    let name = format!("parity-policy-{}", Uuid::new_v4());
    let body = policy_json(&tenant_id, &name);

    let client = Client::new();
    let rest = client
        .post(format!("{base}/v1/policies"))
        .header("Authorization", format!("Bearer {api_key}"))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .expect("REST create_policy");
    assert_eq!(rest.status(), reqwest::StatusCode::CREATED);
    let rest_json: Value = rest.json().await.expect("rest body");

    let channel = tonic::transport::Endpoint::from_shared(format!("http://{}", harness.grpc_addr))
        .expect("grpc endpoint")
        .connect()
        .await
        .expect("grpc connect");

    let mut grpc = PolicyServiceClient::new(channel);
    let rule_id = body["rules"][0]["ruleId"]
        .as_str()
        .expect("ruleId")
        .to_string();
    let rule = PolicyRule {
        rule_id,
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
            scope_id: tenant_id.clone(),
        }),
        name: name.clone(),
        description: "rest-grpc parity".into(),
        default_action: DefaultPolicyAction::Allow as i32,
        rules: vec![rule],
        labels: None,
        create_as_draft: true,
    });
    let meta_val = AsciiMetadataValue::try_from(api_key.as_str()).expect("ascii api key");
    req.metadata_mut().insert("x-api-key", meta_val);

    let grpc_res = grpc
        .create_policy(req)
        .await
        .expect("gRPC create_policy");
    let grpc_policy = grpc_res.into_inner().policy.expect("grpc policy");

    let grpc_as_json = json!({
        "policy": {
            "policyId": grpc_policy.policy_id,
            "version": grpc_policy.version,
            "scopeType": match grpc_policy.scope_type {
                x if x == ScopeType::Org as i32 => "ORG",
                x if x == ScopeType::Workspace as i32 => "WORKSPACE",
                x if x == ScopeType::Project as i32 => "PROJECT",
                x if x == ScopeType::Agent as i32 => "AGENT",
                _ => "UNSPECIFIED",
            },
            "scopeId": grpc_policy.scope_id,
            "status": match grpc_policy.status {
                1 => "DRAFT",
                2 => "ACTIVE",
                3 => "ARCHIVED",
                _ => "UNSPECIFIED",
            },
            "defaultAction": match grpc_policy.default_action {
                x if x == DefaultPolicyAction::Allow as i32 => "ALLOW",
                x if x == DefaultPolicyAction::Deny as i32 => "DENY",
                x if x == DefaultPolicyAction::RequireApproval as i32 => "REQUIRE_APPROVAL",
                _ => "UNSPECIFIED",
            },
            "name": grpc_policy.name,
            "description": grpc_policy.description,
            "rules": grpc_policy.rules.len(),
        }
    });

    let r = comparable_policy_fields(&rest_json);
    let g = (
        grpc_as_json["policy"]["name"].as_str().unwrap().to_string(),
        grpc_as_json["policy"]["version"].to_string(),
        grpc_as_json["policy"]["status"].as_str().unwrap().to_string(),
        grpc_as_json["policy"]["defaultAction"]
            .as_str()
            .unwrap()
            .to_string(),
        grpc_as_json["policy"]["scopeType"].as_str().unwrap().to_string(),
        grpc_as_json["policy"]["rules"].as_u64().unwrap() as usize,
    );
    assert_eq!(r.0, g.0, "name");
    assert_eq!(r.1, g.1, "version");
    assert_eq!(r.2, g.2, "status");
    assert_eq!(r.3, g.3, "defaultAction");
    assert_eq!(r.4, g.4, "scopeType");
    assert_eq!(r.5, g.5, "rules count");

    assert_ne!(
        rest_json["policy"]["policyId"].as_str().unwrap(),
        grpc_as_json["policy"]["policyId"].as_str().unwrap(),
        "distinct creates should yield distinct policy ids"
    );
}

/// **Expected flow**
///
/// 1. For representative error classes (validation, not found, conflict, permission), trigger the same
///    logical failure via REST and gRPC.
/// 2. Assert HTTP status codes align with documented gRPC status codes (e.g. 404 ↔ `NotFound`,
///    409 ↔ `AlreadyExists` or `FailedPrecondition` per API contract).
/// 3. Optionally assert error envelope / `details` parity where the spec requires it.
#[tokio::test]
#[ignore = "requires running agentfirewall-server with REST and gRPC enabled"]
async fn error_codes_map_correctly_between_transports() {
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

    let client = Client::new();
    let invalid_rest = json!({
        "scope": { "scopeType": "ORG", "scopeId": tenant_id },
        "name": "",
        "defaultAction": "ALLOW",
        "rules": [],
        "createAsDraft": true
    });
    let rest = client
        .post(format!("{base}/v1/policies"))
        .header("Authorization", format!("Bearer {api_key}"))
        .header("Content-Type", "application/json")
        .json(&invalid_rest)
        .send()
        .await
        .expect("REST invalid create");
    assert_eq!(
        rest.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "empty name should be 400"
    );

    let channel = tonic::transport::Endpoint::from_shared(format!("http://{}", harness.grpc_addr))
        .expect("grpc endpoint")
        .connect()
        .await
        .expect("grpc connect");

    let mut grpc = PolicyServiceClient::new(channel);
    let mut req = tonic::Request::new(CreatePolicyRequest {
        idempotency: None,
        scope: Some(ResourceScope {
            scope_type: ScopeType::Org as i32,
            scope_id: tenant_id,
        }),
        name: String::new(),
        description: String::new(),
        default_action: DefaultPolicyAction::Allow as i32,
        rules: vec![],
        labels: None,
        create_as_draft: true,
    });
    let meta_val = AsciiMetadataValue::try_from(api_key.as_str()).expect("ascii api key");
    req.metadata_mut().insert("x-api-key", meta_val);

    let err = grpc
        .create_policy(req)
        .await
        .expect_err("gRPC should reject empty name");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}
