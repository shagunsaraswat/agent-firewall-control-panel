//! Approval lifecycle and witness revalidation integration tests.
//!
//! **Infrastructure**: Full stack (Postgres for approvals, optional witness/crypto dependencies as
//! configured in server), `agentfirewall-server` with approval + run services enabled. Fixtures may
//! need a policy and tool context that produces a witness hash for revalidation.
//!
//! Environment:
//! - `AGENTVAULT_TEST_KEY_TENANT_A`, `AGENTVAULT_TEST_TENANT_A_ID`
//!
//! Run ignored tests explicitly:
//! `cargo test -p agentfirewall-integration-tests --test approval_witness_path -- --ignored`

use std::time::Duration;

use agentfirewall_integration_tests::harness::{self, TestHarness};
use reqwest::Client;
use serde_json::{json, Value};
use uuid::Uuid;

fn env_or(var: &str, default: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| default.to_string())
}

/// 32-byte witness as 64 hex chars (server requirement).
fn sample_witness_hash() -> String {
    "a".repeat(64)
}

/// **Expected flow**
///
/// 1. Create an approval in `pending` (or initial) state tied to a run/tool attempt.
/// 2. Resolve the approval (approve/deny per API) and capture `state_witness_hash` / related fields.
/// 3. Invoke the witness revalidation endpoint or RPC with the tuple from the approval.
/// 4. Assert success for a matching witness and failure when hash or approval id is tampered with.
#[tokio::test]
#[ignore = "requires Docker Compose stack, migrated DB, and running agentfirewall-server approval pipeline"]
async fn create_approval_resolve_then_witness_revalidation_end_to_end() {
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
    let agent_id = Uuid::new_v4().to_string();
    let policy_id = Uuid::new_v4().to_string();
    let rule_id = Uuid::new_v4().to_string();
    let witness_hash = sample_witness_hash();
    let cas_uri = "cas://integration-test/witness-bundle";

    let client = Client::new();
    let auth = format!("Bearer {api_key}");

    let run_body = json!({
        "scope": { "scopeType": "ORG", "scopeId": tenant_id },
        "agentId": agent_id,
        "goal": "approval-witness-e2e"
    });
    let run_resp = client
        .post(format!("{base}/v1/runs"))
        .header("Authorization", &auth)
        .header("Content-Type", "application/json")
        .json(&run_body)
        .send()
        .await
        .expect("create run");
    assert_eq!(
        run_resp.status(),
        reqwest::StatusCode::CREATED,
        "{}",
        run_resp.text().await.unwrap_or_default()
    );
    let run_json: Value = run_resp.json().await.expect("run json");
    let run_id = run_json["runId"].as_str().expect("runId").to_string();

    let approval_body = json!({
        "runId": run_id,
        "stepIndex": 0,
        "policyId": policy_id,
        "ruleId": rule_id,
        "reasonCode": "integration.test",
        "requestedBy": "integration-tests",
        "ttl": "600s",
        "witness": {
            "hash": witness_hash,
            "resourceId": cas_uri
        }
    });

    let create_app = client
        .post(format!("{base}/v1/approvals"))
        .header("Authorization", &auth)
        .header("Content-Type", "application/json")
        .json(&approval_body)
        .send()
        .await
        .expect("create approval");
    assert_eq!(
        create_app.status(),
        reqwest::StatusCode::CREATED,
        "{}",
        create_app.text().await.unwrap_or_default()
    );
    let created: Value = create_app.json().await.expect("approval json");
    let approval_id = created["approval"]["approvalId"]
        .as_str()
        .expect("approvalId")
        .to_string();
    assert_eq!(
        created["approval"]["status"].as_str(),
        Some("PENDING"),
        "new approval should start pending"
    );

    let resolve_body = json!({
        "resolution": "APPROVED",
        "resolvedBy": agent_id,
        "comment": "integration approve"
    });
    let resolve = client
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header("Authorization", &auth)
        .header("Content-Type", "application/json")
        .json(&resolve_body)
        .send()
        .await
        .expect("resolve approval");
    assert_eq!(
        resolve.status(),
        reqwest::StatusCode::OK,
        "{}",
        resolve.text().await.unwrap_or_default()
    );
    let resolved: Value = resolve.json().await.expect("resolved json");
    assert_eq!(
        resolved["approval"]["status"].as_str(),
        Some("APPROVED"),
        "approval should be approved after resolve"
    );

    let reval_body = json!({
        "witness": {
            "hash": witness_hash,
            "resourceId": cas_uri
        }
    });
    let reval = client
        .post(format!(
            "{base}/v1/approvals/{approval_id}/revalidate"
        ))
        .header("Authorization", &auth)
        .header("Content-Type", "application/json")
        .json(&reval_body)
        .send()
        .await
        .expect("revalidate");
    assert_eq!(
        reval.status(),
        reqwest::StatusCode::OK,
        "{}",
        reval.text().await.unwrap_or_default()
    );
    let rev_json: Value = reval.json().await.expect("revalidate json");
    assert_eq!(
        rev_json["witnessValid"].as_bool(),
        Some(true),
        "matching witness should validate"
    );
    assert_eq!(
        rev_json["approval"]["status"].as_str(),
        Some("APPROVED"),
        "approval should remain approved after revalidation"
    );

    let bad_hash = "b".repeat(64);
    let bad_reval = json!({
        "witness": {
            "hash": bad_hash,
            "resourceId": cas_uri
        }
    });
    let bad = client
        .post(format!(
            "{base}/v1/approvals/{approval_id}/revalidate"
        ))
        .header("Authorization", &auth)
        .header("Content-Type", "application/json")
        .json(&bad_reval)
        .send()
        .await
        .expect("bad revalidate");
    assert_eq!(bad.status(), reqwest::StatusCode::OK);
    let bad_json: Value = bad.json().await.expect("bad revalidate json");
    assert_eq!(bad_json["witnessValid"].as_bool(), Some(false));
    assert_eq!(
        bad_json["reasonCode"].as_str(),
        Some("WITNESS_HASH_MISMATCH")
    );
}
