<p align="center">
  <img src="docs/assets/logo.png" alt="Agent FirewallKit" width="120" />
</p>

<h1 align="center">Agent FirewallKit</h1>

<p align="center">
  <strong>Runtime safety layer for autonomous AI agents</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="MIT License" /></a>
  <a href="https://github.com/shagunsaraswat/agent-firewall-control-panel/stargazers"><img src="https://img.shields.io/github/stars/shagunsaraswat/agent-firewall-control-panel?style=social" alt="GitHub Stars" /></a>
  <a href="https://github.com/shagunsaraswat/agent-firewall-control-panel/network/members"><img src="https://img.shields.io/github/forks/shagunsaraswat/agent-firewall-control-panel?style=social" alt="GitHub Forks" /></a>
  <img src="https://img.shields.io/badge/rust-1.77%2B-orange.svg" alt="Rust 1.77+" />
  <img src="https://img.shields.io/badge/python-3.9%2B-blue.svg" alt="Python 3.9+" />
  <img src="https://img.shields.io/badge/node-18%2B-green.svg" alt="Node 18+" />
</p>

<p align="center">
  Agent FirewallKit is an open-source control plane that helps you run AI agents with clear boundaries.<br />
  It tracks whether work is progressing, re-checks approvals against live state,<br />
  and turns observed behavior into enforceable policy.<br />
  Built for policy-first AI operations.
</p>

<p align="center"><img src="docs/assets/hero-banner.png" alt="Agent FirewallKit — Runtime safety for autonomous agents" width="100%" /></p>

---

## The Problem

You deploy an autonomous AI agent to refactor a codebase. Within minutes:

- It **loops** on the same file, burning tokens without progress
- It **writes to production config** that was only approved for staging
- It **calls a shell command** your policy explicitly forbids
- The **state it was approved to modify has changed** since the human said "yes"
- Nobody notices until the damage is done

Agent FirewallKit exists to catch every one of these before they happen.

<p align="center"><img src="docs/assets/problem-scenario.png" alt="Without guardrails vs With Agent FirewallKit" width="90%" /></p>

## Why Agent FirewallKit?

<p align="center">
  <img src="docs/assets/feature-sentinel.png" alt="Sentinel — Progress Tracking" width="30%" />
  <img src="docs/assets/feature-witness.png" alt="Witness — State Revalidation" width="30%" />
  <img src="docs/assets/feature-learner.png" alt="Learner — Observe, Learn, Enforce" width="30%" />
</p>

| Module | What it solves | How it works |
|--------|---------------|-------------|
| **Sentinel** | Agent is looping, stalled, or regressing | Tracks semantic progress via embeddings. Compares each step's state against the goal vector. Detects when cosine similarity stops improving (stall) or drops (regression). Escalates: Warn → Downgrade → Pause → Deny. |
| **Witness** | Approved state has changed since approval | Captures a SHA-256 hash of the state at approval time. Before execution, re-hashes the current state and compares. If the world changed, blocks execution with `WITNESS_HASH_MISMATCH`. |
| **Learner** | Writing security rules by hand is tedious and incomplete | Observes agent behavior via NATS telemetry spans. Builds statistical baselines of "normal" tool usage, cost patterns, and action frequencies. Generates policy candidates you can review and promote to enforceable rules. |

## How It Connects to Your Agent

<p align="center"><img src="docs/assets/architecture-overview.png" alt="Agent FirewallKit Architecture — Two-layer system" width="90%" /></p>

Agent FirewallKit has two layers that work together:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Your Agent / Host Process                    │
│                                                                  │
│   from agentfirewall import PolicyEvaluator, WitnessGuard          │
│   from agentfirewall.sentinel import SentinelTracker               │
│                                                                  │
│   ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐ │
│   │ Policy       │  │ Sentinel     │  │ Witness Guard         │ │
│   │ Evaluator    │  │ Tracker      │  │ (capture + verify)    │ │
│   │              │  │              │  │                       │ │
│   │ Before every │  │ Each step:   │  │ At approval: hash     │ │
│   │ tool call →  │  │ progress     │  │ current state.        │ │
│   │ Allow/Deny/  │  │ check →      │  │ Before execution:     │ │
│   │ Require      │  │ Warn/Block   │  │ re-hash → match?      │ │
│   │ Approval     │  │ if looping   │  │ Yes → proceed         │ │
│   │              │  │              │  │ No  → block           │ │
│   └──────────────┘  └──────────────┘  └───────────────────────┘ │
│         All three run IN-PROCESS (no network latency)            │
│                                                                  │
│   ┌──────────────────────────────────────────────────────────┐   │
│   │ Learner Client → emits telemetry spans to NATS           │   │
│   └─────────────────────────┬────────────────────────────────┘   │
└─────────────────────────────┼────────────────────────────────────┘
                              │
                    HTTP / gRPC calls for:
                    • Loading policies from server
                    • Creating runs, approvals, incidents
                    • Resolving approvals (human-in-the-loop)
                    • Querying learner baselines & candidates
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Agent FirewallKit Control Plane                        │
│                                                                  │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │
│   │ Policy   │  │ Run      │  │ Approval │  │ Incident     │   │
│   │ Service  │  │ Service  │  │ Service  │  │ Service      │   │
│   │          │  │          │  │          │  │              │   │
│   │ Store &  │  │ Track    │  │ Human-   │  │ Track rule   │   │
│   │ version  │  │ agent    │  │ in-the-  │  │ violations   │   │
│   │ rules    │  │ runs     │  │ loop     │  │ with sev &   │   │
│   │          │  │          │  │ + witness│  │ remediation  │   │
│   └──────────┘  └──────────┘  └──────────┘  └──────────────┘   │
│   ┌──────────────────────────────────────────────────────────┐   │
│   │ Learner Service │ Span Ingest  │ Baseline Aggregator     │   │
│   └──────────────────────────────────────────────────────────┘   │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │
│   │PostgreSQL│  │ClickHouse│  │   NATS   │  │    Redis     │   │
│   └──────────┘  └──────────┘  └──────────┘  └──────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### What runs where

| Component | Where it runs | Network needed? | What it does |
|-----------|--------------|-----------------|-------------|
| **PolicyEvaluator** | In your agent process | No | Evaluates rules locally against each action. Microsecond latency. |
| **SentinelTracker** | In your agent process | No | Embeds step summaries, computes progress delta, detects anomalies. |
| **WitnessGuard** | In your agent process | No | SHA-256 hashing and constant-time comparison of state snapshots. |
| **LearnerClient** | In your agent process | Yes (NATS) | Publishes `SpanEvent` telemetry to NATS for server-side aggregation. |
| **Control Plane** | Docker / Kubernetes | Yes (HTTP/gRPC) | Stores policies, tracks runs, manages approvals, processes incidents, learns baselines. |

### Integration code

<p align="center"><img src="docs/assets/sdk-integration.png" alt="Agent FirewallKit SDK in a single agent step" width="60%" /></p>

**Python** (via PyO3 bindings):

```python
from agentfirewall.core import PolicyEvaluator, RunContextManager
from agentfirewall.sentinel import SentinelTracker
from agentfirewall.witness import WitnessGuard
from agentfirewall.learner import LearnerClient

# 1. Load policies (from server or local file)
evaluator = PolicyEvaluator()
evaluator.load_rules_json(rules_json)

# 2. Before every tool call: check policy
decision = evaluator.evaluate("TOOL", "execute_shell", context)
if decision == "DENY":
    raise BlockedAction("Policy denied this tool")

# 3. Track progress with Sentinel
sentinel = SentinelTracker(config={"stall_window": 5})
sentinel.register_goal(run_id, "Refactor auth to JWT")
result = sentinel.evaluate_step(run_id, step_index, "Reading auth module...")
if result.get("intervention"):
    handle_intervention(result["intervention"])

# 4. Capture witness hash for approvals
guard = WitnessGuard()
snapshot = guard.capture_json('{"file": "config.yml", "content": "..."}', "file://config.yml")
# Store snapshot.hash with the approval request

# 5. Before executing approved action: verify state hasn't changed
result = guard.verify_json(snapshot, current_file_content_json)
if not result["valid"]:
    raise StaleApproval("State changed since approval: " + result["reason_code"])

# 6. Emit telemetry for Learner
learner = LearnerClient({"nats_url": "nats://localhost:4222", "tenant_id": "..."})
await learner.connect()
await learner.emit_span({"kind": "TOOL_CALL", "tool_name": "read_file", ...})
```

**Rust** (native):

```rust
use agentfirewall_core::policy::{PolicyEvaluator, PolicyEvaluatorHandle};
use agentfirewall_core::run::RunContextManager;
use agentfirewall_sentinel::SentinelTracker;
use agentfirewall_witness::WitnessGuard;

let evaluator = PolicyEvaluatorHandle::new(/* ... */);
let decision = evaluator.evaluate(&run_context, &action);

let sentinel = SentinelTracker::new(config, embed_handle);
sentinel.register_goal(run_id, "Refactor auth module");
let eval = sentinel.evaluate_step(run_id, 1, "Analyzing file structure...");

let guard = WitnessGuard::new();
let snapshot = guard.capture_json_for_approval(&state_json, "file://config.yml")?;
let result = guard.verify_json_before_execution(&snapshot, &current_json)?;
```

**Node.js / TypeScript** (via NAPI-RS):

```typescript
import { PolicyEvaluator, RunContextManager, WitnessGuard, LearnerClient } from '@agentfirewall/node';

const evaluator = new PolicyEvaluator();
evaluator.loadRulesJson(rulesJson);
const decision = evaluator.evaluate('TOOL', 'read_file', context);

const guard = new WitnessGuard();
const snapshot = guard.captureJson(stateJson, 'file://config.yml');
const result = guard.verifyJson(snapshot, currentJson);
```

### Connecting to the control plane

Your agent talks to the control plane server via HTTP or gRPC for operations that need persistence and coordination:

```bash
# These are the API calls your agent makes to the server:

# Load policies for this tenant
GET  /v1/policies?scopeId={tenant}&scopeType=ORG

# Report that a run has started
POST /v1/runs  { agentId, scope, mode, goal }

# Request human approval for a dangerous action
POST /v1/approvals  { runId, witness: { hash }, reasonCode }

# Report a policy violation
POST /v1/incidents  { severity, reasonCode, title, runId }

# Mark run complete
POST /v1/runs/{id}/complete  { terminalStatus: "COMPLETED" }
```

## How It Works: End-to-End Scenario

<p align="center"><img src="docs/assets/workflow-approval.png" alt="End-to-end approval workflow with witness revalidation" width="90%" /></p>

Here is a concrete scenario showing every component in action. This exact flow has been tested against the running Docker stack.

### Scenario: Code refactoring agent with guardrails

```
Step 1 — OPERATOR defines a policy
         ┌─────────────────────────────────────┐
         │  "code-agent-guardrails"             │
         │                                      │
         │  Default: DENY everything            │
         │  Rule 1: ALLOW tool "read_file"      │
         │  Rule 2: ALLOW tool "search_code"    │
         │  Rule 3: REQUIRE_APPROVAL for writes │
         │  Rule 4: DENY tool "execute_shell"   │
         └─────────────────────────────────────┘
                        │
Step 2 — AGENT starts a run
         Run created: status=PENDING, goal="Refactor auth to JWT"
                        │
Step 3 — AGENT reads files (policy: ALLOW) ✓
         Sentinel: progress 0.0 → 0.34 (healthy)
                        │
Step 4 — AGENT wants to write src/auth/jwt.rs
         Policy evaluator returns: REQUIRE_APPROVAL
         Agent captures witness hash of current file state
         Agent creates approval request with hash
                        │
Step 5 — HUMAN reviews and approves ✓
                        │
Step 6 — Before writing, WITNESS revalidates
         Current file hash == approved hash? YES → proceed
                        │
Step 7 — Meanwhile, another process modifies the file...
                        │
Step 8 — Agent's SECOND write attempt
         Witness revalidation: hash MISMATCH
         Result: witnessValid=false, reasonCode=WITNESS_HASH_MISMATCH
         Action BLOCKED — stale approval
                        │
Step 9 — AGENT tries execute_shell
         Policy evaluator returns: DENY (reason: SHELL_BLOCKED)
         Incident auto-created: severity=HIGH
                        │
Step 10 — Run completes: status=COMPLETED
          Learner has been observing all spans via NATS
          Learner proposes tighter policy based on observed behavior
```

### Testing this scenario against your Docker stack

After running `./start.sh`, execute these commands to walk through the entire flow:

```bash
export API_KEY="your-api-key-here"
export TENANT="your-tenant-uuid"

# Step 1: Create the policy
curl -X POST http://localhost:8080/v1/policies \
  -H "x-api-key: $API_KEY" -H "Content-Type: application/json" \
  -d '{
    "scope": {"scopeType": "ORG", "scopeId": "'"$TENANT"'"},
    "name": "code-agent-guardrails",
    "description": "Allow reads, require approval for writes, deny shell",
    "defaultAction": "DENY",
    "rules": [
      {"ruleId":"00000000-0000-0000-0000-000000000010","priority":10,
       "targetType":"TOOL","targetSelector":"read_file",
       "action":"ALLOW","reasonCode":"SAFE_READ","enabled":true},
      {"ruleId":"00000000-0000-0000-0000-000000000030","priority":30,
       "targetType":"WRITE_ACTION","targetSelector":"*",
       "action":"REQUIRE_APPROVAL","reasonCode":"WRITE_NEEDS_REVIEW","enabled":true},
      {"ruleId":"00000000-0000-0000-0000-000000000040","priority":40,
       "targetType":"TOOL","targetSelector":"execute_shell",
       "action":"DENY","reasonCode":"SHELL_BLOCKED","enabled":true}
    ]
  }'

# Step 2: Start a run
RUN=$(curl -s -X POST http://localhost:8080/v1/runs \
  -H "x-api-key: $API_KEY" -H "Content-Type: application/json" \
  -d '{
    "scope": {"scopeType":"ORG","scopeId":"'"$TENANT"'"},
    "agentId": "11111111-1111-1111-1111-111111111111",
    "mode": "enforce",
    "goal": "Refactor auth module to use JWT"
  }')
RUN_ID=$(echo $RUN | python3 -c "import sys,json; print(json.load(sys.stdin)['runId'])")
echo "Run: $RUN_ID"

# Step 3: Create approval with witness hash (64 hex chars = 32 bytes SHA-256)
WITNESS_HASH="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
APPR=$(curl -s -X POST http://localhost:8080/v1/approvals \
  -H "x-api-key: $API_KEY" -H "Content-Type: application/json" \
  -d '{
    "runId": "'"$RUN_ID"'",
    "stepIndex": 3,
    "policyId": "POLICY_ID_FROM_STEP_1",
    "ruleId": "00000000-0000-0000-0000-000000000030",
    "reasonCode": "WRITE_NEEDS_REVIEW",
    "requestedBy": "agent-codegen",
    "witness": {"hash": "'"$WITNESS_HASH"'", "resourceId": "file://src/auth/jwt.rs"},
    "ttlSeconds": 1800
  }')
APPROVAL_ID=$(echo $APPR | python3 -c "import sys,json; print(json.load(sys.stdin)['approval']['approvalId'])")
echo "Approval: $APPROVAL_ID"

# Step 4: Revalidate witness — state UNCHANGED (should return witnessValid: true)
curl -s -X POST "http://localhost:8080/v1/approvals/$APPROVAL_ID/revalidate" \
  -H "x-api-key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"witness":{"hash":"'"$WITNESS_HASH"'","resourceId":"file://src/auth/jwt.rs"}}'
# Response: { "witnessValid": true, "reasonCode": "" }

# Step 5: Revalidate witness — state CHANGED (should return witnessValid: false)
curl -s -X POST "http://localhost:8080/v1/approvals/$APPROVAL_ID/revalidate" \
  -H "x-api-key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"witness":{"hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","resourceId":"file://src/auth/jwt.rs"}}'
# Response: { "witnessValid": false, "reasonCode": "WITNESS_HASH_MISMATCH" }

# Step 6: Open incident for blocked tool
curl -s -X POST http://localhost:8080/v1/incidents \
  -H "x-api-key: $API_KEY" -H "Content-Type: application/json" \
  -d '{
    "scope": {"scopeType":"ORG","scopeId":"'"$TENANT"'"},
    "severity": "HIGH",
    "reasonCode": "SHELL_BLOCKED",
    "title": "Agent attempted execute_shell",
    "summary": "Agent tried: rm -rf /tmp/build && make deploy",
    "runId": "'"$RUN_ID"'"
  }'

# Step 7: Acknowledge and manage the incident
INCIDENT_ID="<id-from-step-6>"
curl -s -X POST "http://localhost:8080/v1/incidents/$INCIDENT_ID/acknowledge" \
  -H "x-api-key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"acknowledgedBy":"operator-alice"}'

# Step 8: Complete the run
curl -s -X POST "http://localhost:8080/v1/runs/$RUN_ID/complete" \
  -H "x-api-key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"terminalStatus":"COMPLETED"}'

# Step 9: Enable learner to observe
curl -s -X PUT http://localhost:8080/v1/learner/mode \
  -H "x-api-key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"scope":{"scopeType":"ORG","scopeId":"'"$TENANT"'"},"mode":"MONITOR"}'

# Step 10: Check everything in metrics
curl -s http://localhost:9090/metrics | grep agentfirewall_request_count
```

### What each test proves

| Test | What it validates |
|------|------------------|
| Create policy + list | Policy CRUD, tenant-scoped storage, rule serialization |
| Create run | Run lifecycle management, status transitions |
| Create approval with witness | Witness hash storage, TTL-based expiration, approval workflow |
| Revalidate (same hash) | `witnessValid: true` — state integrity confirmed |
| Revalidate (different hash) | `witnessValid: false` + `WITNESS_HASH_MISMATCH` — tamper detection works |
| Create incident | Security event tracking, severity classification |
| Acknowledge incident | OPEN → ACKNOWLEDGED state transition |
| Complete run | PENDING → COMPLETED terminal transition |
| Set learner mode | Learner configuration, Redis-backed mode storage |
| Idempotency (same key twice) | Returns cached response, no duplicate creation |
| No API key | Returns 401 with structured error envelope |
| Metrics endpoint | Prometheus counters per method/path/status |

### Additional test commands

```bash
# Security: no auth → 401 with request_id
curl -s http://localhost:8080/v1/policies
# {"error":{"code":"AUTH_INVALID_CREDENTIALS","message":"Invalid credentials.","request_id":"..."}}

# Idempotency: repeat same create with same key → cached response
curl -X POST http://localhost:8080/v1/policies \
  -H "x-api-key: $API_KEY" -H "Idempotency-Key: unique-key-123" \
  -H "Content-Type: application/json" -d '{...}'
# First call: creates resource. Second call: returns same response from cache.

# Health probes
curl http://localhost:8080/healthz    # 200 (liveness)
curl http://localhost:8080/readyz     # 200 (DB + Redis + NATS healthy)

# Prometheus metrics
curl http://localhost:9090/metrics | grep agentfirewall_

# Server logs (structured JSON)
docker logs agentfirewall-server -f
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Core language | Rust |
| Python bindings | PyO3 |
| TypeScript / Node bindings | NAPI-RS |
| HTTP server | Axum |
| gRPC server | Tonic |
| Primary database | PostgreSQL |
| Analytics database | ClickHouse |
| Event streaming | NATS (JetStream) |
| Caching | Redis / Valkey |
| Embeddings | FastEmbed-rs (ONNX) |

## Quick Start

### One-command Docker setup

```bash
git clone https://github.com/shagunsaraswat/agent-firewall-control-panel.git
cd agent-firewall-control-panel
./start.sh
```

This builds the server, starts all dependencies (Postgres, ClickHouse, NATS, Redis), waits for health, and prints connection info:

```
═══════════════════════════════════════════════════
  Agent FirewallKit Development Stack Running
═══════════════════════════════════════════════════

  HTTP API:            http://localhost:8080
  gRPC:                localhost:50051
  Metrics:             http://localhost:9090/metrics
  PostgreSQL:          localhost:5432
  ClickHouse:          http://localhost:8123
  NATS:                localhost:4222
  Redis:               localhost:6379
```

### Create an API key

Connect to the running Postgres and insert a key:

```bash
# Generate a random key
RAW_KEY="av_$(openssl rand -hex 24)"
KEY_HASH=$(printf '%s' "$RAW_KEY" | shasum -a 256 | cut -d' ' -f1)
KEY_PREFIX=$(echo "$RAW_KEY" | head -c 8)
TENANT_ID="$(uuidgen | tr '[:upper:]' '[:lower:]')"

# Insert into the database
docker exec agentfirewall-postgres psql -U agentfirewall -d agentfirewall -c \
  "INSERT INTO api_keys (tenant_id, name, key_hash, key_prefix, permissions)
   VALUES ('$TENANT_ID', 'dev-admin', decode('$KEY_HASH', 'hex'), '$KEY_PREFIX', ARRAY['Admin']::text[]);"

echo "API Key: $RAW_KEY"
echo "Tenant:  $TENANT_ID"
```

### Verify it works

```bash
# Health (no auth needed)
curl http://localhost:8080/healthz
curl http://localhost:8080/readyz

# Authenticated request
curl -s "http://localhost:8080/v1/policies?scopeId=$TENANT_ID&scopeType=ORG" \
  -H "x-api-key: $RAW_KEY" | python3 -m json.tool
```

### From source (no Docker)

```bash
cargo build --workspace
cargo test --workspace
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```

## API Reference

Agent FirewallKit exposes both REST (HTTP/JSON) and gRPC APIs with full parity. All REST endpoints live under `/v1/`.

### Authentication

Every `/v1/*` request requires one of:

| Method | Header |
|--------|--------|
| API Key | `x-api-key: <key>` |
| Bearer Token | `Authorization: Bearer <key>` |

### Idempotency

Mutating endpoints (all `POST` creates) accept an optional `Idempotency-Key` header. Same key + same operation returns the cached response without re-executing. Keys expire after 5 minutes (configurable via `AV_IDEMPOTENCY_TTL_SECS`).

### Endpoints

#### Policies — define what agents can and cannot do

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/policies` | Create a new policy |
| `GET` | `/v1/policies` | List policies for a scope |
| `GET` | `/v1/policies/:id` | Get a policy by ID |
| `POST` | `/v1/policies/:id/activate` | Activate a policy (with optimistic concurrency via `etag`) |
| `POST` | `/v1/policies/:id/deactivate` | Deactivate a policy |

#### Runs — track agent execution lifecycle

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/runs` | Create an agent run |
| `GET` | `/v1/runs` | List runs for a scope |
| `GET` | `/v1/runs/:id` | Get a run by ID |
| `POST` | `/v1/runs/:id/complete` | Mark run as COMPLETED or FAILED |
| `POST` | `/v1/runs/:id/cancel` | Cancel a run |

#### Approvals — human-in-the-loop checkpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/approvals` | Create an approval request (requires witness hash) |
| `GET` | `/v1/approvals` | List approvals |
| `GET` | `/v1/approvals/:id` | Get an approval |
| `POST` | `/v1/approvals/:id/resolve` | Approve, reject, escalate, or cancel |
| `POST` | `/v1/approvals/:id/revalidate` | Re-check witness validity against current state |

#### Incidents — track and respond to security violations

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/incidents` | Open an incident |
| `GET` | `/v1/incidents` | List incidents |
| `GET` | `/v1/incidents/:id` | Get an incident |
| `POST` | `/v1/incidents/:id/acknowledge` | Acknowledge an incident |
| `POST` | `/v1/incidents/:id/resolve` | Resolve an incident |

#### Learner — observe behavior and generate policies

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/learner/mode` | Get learner mode for a scope |
| `PUT` | `/v1/learner/mode` | Set learner mode (MONITOR, ENFORCE, AUTO_PROMOTE_SAFE) |
| `GET` | `/v1/learner/baseline` | Get behavioral baseline signals |
| `GET` | `/v1/learner/candidates` | List policy candidates |
| `GET` | `/v1/learner/candidates/:id` | Get a candidate |
| `POST` | `/v1/learner/candidates/:id/approve` | Approve a candidate (optionally promote to policy) |
| `POST` | `/v1/learner/candidates/:id/reject` | Reject a candidate |
| `POST` | `/v1/learner/generate` | Queue a policy generation job |

#### Infrastructure — health and observability

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/healthz` | Liveness probe (always 200) |
| `GET` | `/readyz` | Readiness probe (checks DB, Redis, NATS) |
| `GET` | `/metrics` | Prometheus metrics scrape endpoint |

### Error Envelope

All errors follow a consistent JSON structure:

```json
{
  "error": {
    "code": "INVALID_ARGUMENT",
    "message": "scope_id is required",
    "reason_code": "MISSING_SCOPE",
    "request_id": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

### gRPC

The same services are available over gRPC at port `50051` with metadata-based auth (`x-api-key`) and idempotency (`x-idempotency-key`). Proto definitions live in `proto/agentfirewall/`.

## CLI

<p align="center"><img src="docs/assets/cli-screenshot.png" alt="Agent FirewallKit CLI — policy list, incident list, server health" width="70%" /></p>

Agent FirewallKit includes a CLI for managing the control plane:

```bash
# Set connection info
export AV_API_KEY="av_..."
export AV_SERVER_URL="http://127.0.0.1:50051"
export AV_TENANT_ID="550e8400-..."

# Policy management
agentfirewall policy list
agentfirewall policy get <policy-id>
agentfirewall policy create --name "my-policy" --rules rules.json
agentfirewall policy activate <policy-id>
agentfirewall policy validate rules.json    # Local validation, no server needed

# Run management
agentfirewall run list
agentfirewall run get <run-id>
agentfirewall run cancel <run-id>

# Incident management
agentfirewall incident list --severity 3
agentfirewall incident get <incident-id>
agentfirewall incident ack <incident-id>
agentfirewall incident resolve <incident-id> --note "Resolved"

# Approval management
agentfirewall approval list --status PENDING
agentfirewall approval approve <approval-id>
agentfirewall approval deny <approval-id> --reason "Unsafe"

# Witness inspection
agentfirewall witness inspect <approval-id>
agentfirewall witness verify <approval-id>

# Learner
agentfirewall learner status
agentfirewall learner set-mode MONITOR
agentfirewall learner candidates
agentfirewall learner baseline

# Server health
agentfirewall server health

# JSON output (for scripts and automation)
agentfirewall --json policy list
```

## Configuration

All server configuration is via environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `AV_DATABASE_URL` | Yes | — | PostgreSQL connection string |
| `AV_LISTEN_ADDR` | No | `0.0.0.0:8080` | HTTP listen address |
| `AV_GRPC_ADDR` | No | `0.0.0.0:50051` | gRPC listen address |
| `AV_METRICS_ADDR` | No | `0.0.0.0:9090` | Prometheus metrics address |
| `AV_REDIS_URL` | No | `redis://localhost:6379` | Redis connection (optional; degrades gracefully) |
| `AV_NATS_URL` | No | `nats://localhost:4222` | NATS connection (optional; degrades gracefully) |
| `AV_CLICKHOUSE_URL` | No | `http://localhost:8123` | ClickHouse for analytics (optional) |
| `AV_HTTP_API_ENABLED` | No | `true` | Enable REST API alongside gRPC |
| `AV_MAX_DB_CONNECTIONS` | No | `20` | PostgreSQL connection pool size |
| `AV_REQUEST_TIMEOUT_SECS` | No | `30` | HTTP client timeout for webhooks |
| `AV_CORS_ORIGINS` | No | `*` | Comma-separated allowed origins |
| `AV_TLS_CERT_PATH` | No | — | TLS certificate path (pair with key) |
| `AV_TLS_KEY_PATH` | No | — | TLS private key path (pair with cert) |
| `AV_IDEMPOTENCY_TTL_SECS` | No | `300` | Idempotency key expiration |

## Database Schema

<p align="center"><img src="docs/assets/database-schema.png" alt="Agent FirewallKit database schema — 10 PostgreSQL tables" width="90%" /></p>

The control plane uses PostgreSQL with 10 tables:

| Table | Purpose |
|-------|---------|
| `policies` | Policy metadata (name, slug, tenant scope) |
| `policy_versions` | Versioned policy content with status lifecycle (draft → active → archived) |
| `policy_rules` | Individual rules within a policy version |
| `runs` | Agent run lifecycle (pending → running → completed/failed/cancelled) |
| `run_steps` | Per-step telemetry and decisions (time-partitioned) |
| `approvals` | Human-in-the-loop approval requests with witness hashes and TTL |
| `incidents` | Security incidents with severity, acknowledgement, and resolution workflow |
| `policy_candidates` | Learner-generated policy candidates awaiting review |
| `api_keys` | SHA-256 hashed API keys with per-key permissions |
| `idempotency_keys` | Server-side idempotency replay protection |

Migrations are in `migrations/postgres/` and run automatically on server startup.

## Security Model

<p align="center"><img src="docs/assets/security-model.png" alt="Agent FirewallKit security model — defense in depth" width="70%" /></p>

| Layer | Mechanism |
|-------|-----------|
| **Tenant isolation** | All data queries are scoped by `tenant_id` derived from the authenticated API key. Cross-tenant access is impossible by design. |
| **RBAC** | Per-key permissions: `PolicyRead`, `PolicyWrite`, `RunRead`, `RunWrite`, `ApprovalRead`, `ApprovalWrite`, `IncidentRead`, `IncidentWrite`, `LearnerRead`, `LearnerWrite`, `Admin`. |
| **API key hashing** | Keys are SHA-256 hashed at rest. Only the 8-character prefix is stored in cleartext for identification. |
| **TLS** | Optional TLS for gRPC via `AV_TLS_CERT_PATH` / `AV_TLS_KEY_PATH`. |
| **Idempotency** | Server-side replay protection prevents duplicate resource creation from retried requests. |
| **Witness revalidation** | Approvals carry a content hash that is re-checked at execution time, preventing stale approvals from authorizing changed state. |
| **Audit log** | Append-only, time-partitioned audit trail with immutability triggers (updates and deletes are rejected by the database). |

## Docker

### Development (full stack)

```bash
./start.sh
```

### Data services only (run server from source)

```bash
docker compose -f docker/docker-compose.yml up -d postgres clickhouse nats redis
export AV_DATABASE_URL=postgres://agentfirewall:agentfirewall@localhost:5432/agentfirewall
cargo run -p agentfirewall-server
```

### Stop

```bash
docker compose -f docker/docker-compose.yml down
```

### Clean (remove volumes)

```bash
docker compose -f docker/docker-compose.yml down -v
```

## Project Structure

```
agent-firewall-control-panel/
├── crates/
│   ├── agentfirewall-core/       # Core types, policy evaluator, witness guard, run manager
│   ├── agentfirewall-embed/      # FastEmbed-rs ONNX semantic embeddings
│   ├── agentfirewall-sentinel/   # Goal-aware progress tracking & intervention engine
│   ├── agentfirewall-witness/    # State-witness capture, hashing, and revalidation
│   ├── agentfirewall-learner/    # Behavioral baseline learning & NATS span emission
│   ├── agentfirewall-server/     # Control plane server (Axum HTTP + Tonic gRPC)
│   ├── agentfirewall-cli/        # CLI client
│   ├── agentfirewall-python/     # PyO3 Python bindings
│   └── agentfirewall-node/       # NAPI-RS Node.js bindings
├── proto/                     # Protobuf service definitions (5 services, 37 RPCs)
├── migrations/                # PostgreSQL DDL migrations (auto-run on startup)
├── tests/integration/         # Integration test suite (tenant isolation, parity, etc.)
├── bindings/
│   ├── python/                # Python SDK test suite
│   └── node/                  # Node.js SDK test suite
├── docker/
│   ├── docker-compose.yml     # Full development stack (5 services)
│   └── .env.example           # Environment template
├── adrs/                      # Architecture Decision Records
├── docs/assets/               # Architecture diagrams, feature cards, and visual assets
├── Dockerfile                 # Multi-stage server build (cargo-chef for layer caching)
└── start.sh                   # One-command dev startup
```

## SDK Bindings

### Python

```bash
cd crates/agentfirewall-python
pip install maturin
maturin develop

# Run tests
cd bindings/python
pytest
```

```python
from agentfirewall.core import PolicyEvaluator, RunContextManager, ReasonCodeRegistry
from agentfirewall.sentinel import SentinelTracker
from agentfirewall.witness import WitnessGuard
from agentfirewall.learner import LearnerClient
```

### Node.js / TypeScript

```bash
cd crates/agentfirewall-node
npm install && npm run build

# Run tests
cd bindings/node
npm test
```

```typescript
import { PolicyEvaluator, RunContextManager, WitnessGuard, LearnerClient } from '@agentfirewall/node';
```

## Observability

<p align="center"><img src="docs/assets/metrics-dashboard.png" alt="Agent FirewallKit Grafana dashboard — request rate, latency, incidents" width="90%" /></p>

- **Logs**: Structured JSON via `tracing` with `tenant_id`, `run_id`, `request_id` in every log line
- **Metrics**: Prometheus-compatible at `/metrics` — request counts by method/path/status, latencies, DB pool stats, active connections
- **Tracing**: OpenTelemetry-compatible spans via NATS for distributed trace propagation

```bash
RUST_LOG=info                          # Default
RUST_LOG=agentfirewall_server=debug       # Debug server only
RUST_LOG=agentfirewall_server=trace       # Trace everything
```

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, style, and the pull request process.

### Running CI checks locally

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

For integration tests (requires Docker):

```bash
docker compose -f docker/docker-compose.yml up -d
cargo test -p agentfirewall-integration-tests -- --include-ignored
```

## Governance

This project uses [BDFL governance](GOVERNANCE.md). Interaction is governed by the [Contributor Covenant](CODE_OF_CONDUCT.md).

## License

[MIT License](LICENSE) — Copyright (c) 2026 Agent FirewallKit Contributors

---

<p align="center">
  <strong>If Agent FirewallKit is useful to you, consider giving it a star — it helps others discover the project.</strong>
</p>

<p align="center">
  <a href="https://github.com/shagunsaraswat/agent-firewall-control-panel/stargazers"><img src="https://img.shields.io/github/stars/shagunsaraswat/agent-firewall-control-panel?style=for-the-badge&logo=github&label=Star%20on%20GitHub" alt="Star on GitHub" /></a>
</p>
