mod client;
mod grpc;

use client::AvCliError;
use std::collections::BTreeMap;
use std::path::Path;

use agentfirewall_core::{
    ActionDescriptor, ActionType, BudgetSnapshot, CompiledPolicySet, PolicyEvaluator, RunContext,
    RunMode,
};
use anyhow::{anyhow, Context, Result};
use chrono::{TimeZone, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Table};
use grpc::approval_v1::{
    approval_service_client::ApprovalServiceClient, Approval, ApprovalStatus, GetApprovalRequest,
    ListApprovalsRequest, RevalidateApprovalRequest, ResolveApprovalRequest, WitnessBundle,
};
use grpc::common_v1::{PageRequest, ResourceScope, ScopeType};
use grpc::incident_v1::{
    incident_service_client::IncidentServiceClient, AcknowledgeIncidentRequest, GetIncidentRequest,
    IncidentSeverity, IncidentStatus, ListIncidentsRequest, ResolveIncidentRequest,
};
use grpc::learner_v1::{
    ApproveCandidateRequest, CandidateStatus, GetBaselineRequest, GetModeRequest, LearnerMode,
    ListCandidatesRequest, RejectCandidateRequest, SetModeRequest,
};
use grpc::policy_v1::{
    policy_service_client::PolicyServiceClient, ActivatePolicyRequest, CreatePolicyRequest,
    DeactivatePolicyRequest, DefaultPolicyAction, GetPolicyRequest, ListPoliciesRequest, Policy,
    PolicyRule, RuleAction, RuleTargetType,
};
use grpc::run_v1::{
    run_service_client::RunServiceClient, CancelRunRequest, GetRunRequest, ListRunsRequest,
    RunStatus,
};
use grpc::LearnerServiceClient;
use prost_types::value::Kind;
use prost_types::{Struct, Value as ProstValue};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Parser, Clone)]
#[command(
    name = "agentfirewall",
    about = "Agent FirewallKit CLI — policy management and operator workflows"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Output results as JSON for automation and piping
    #[arg(long, global = true)]
    json: bool,

    /// API key sent as `x-api-key` gRPC metadata (or set `AV_API_KEY`)
    #[arg(long, global = true, env = "AV_API_KEY")]
    api_key: Option<String>,
}

#[derive(Subcommand, Clone)]
enum Commands {
    /// Learner observe-to-enforce workflows
    #[command(subcommand)]
    Learner(LearnerCommands),
    /// Manage policies
    #[command(subcommand)]
    Policy(PolicyCommands),
    /// Inspect and control runs
    #[command(subcommand)]
    Run(RunCommands),
    /// Manage incidents
    #[command(subcommand)]
    Incident(IncidentCommands),
    /// Manage human approvals
    #[command(subcommand)]
    Approval(ApprovalCommands),
    /// HTTP health and server metadata
    #[command(subcommand)]
    Server(ServerCommands),
    /// Inspect and manage witness records
    #[command(subcommand)]
    Witness(WitnessCommands),
}

#[derive(Subcommand, Clone)]
enum LearnerCommands {
    Status,
    SetMode {
        mode: String,
    },
    Candidates,
    Approve {
        id: String,
    },
    Reject {
        id: String,
        #[arg(long)]
        reason: String,
    },
    Baseline,
}

#[derive(Subcommand, Clone)]
enum PolicyCommands {
    /// List policies for the tenant scope
    List {
        #[arg(long, value_enum)]
        status: Option<PolicyStatusCli>,
    },
    /// Show one policy including rules
    Get { policy_id: String },
    /// Create a draft policy from a rules JSON file
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        description: String,
        #[arg(long)]
        rules: std::path::PathBuf,
    },
    /// Activate a policy (fetches current etag automatically)
    Activate { policy_id: String },
    /// Deactivate a policy (fetches current etag automatically)
    Deactivate { policy_id: String },
    /// Validate a compiled policy-set JSON file locally using `PolicyEvaluator`
    Validate { file: std::path::PathBuf },
}

#[derive(Subcommand, Clone)]
enum RunCommands {
    List {
        #[arg(long, value_enum)]
        status: Option<RunStatusCli>,
    },
    Get {
        run_id: String,
    },
    Cancel {
        run_id: String,
    },
}

#[derive(Subcommand, Clone)]
enum IncidentCommands {
    List {
        #[arg(long, value_enum)]
        status: Option<IncidentStatusCli>,
        /// Minimum severity (1=info … 5=critical); maps to API `severity_at_least`
        #[arg(long)]
        severity: Option<u8>,
    },
    Get {
        incident_id: String,
    },
    Ack {
        incident_id: String,
    },
    Resolve {
        incident_id: String,
        #[arg(long)]
        note: String,
    },
}

#[derive(Subcommand, Clone)]
enum ApprovalCommands {
    List {
        #[arg(long, value_enum)]
        status: Option<ApprovalStatusCli>,
    },
    Get {
        approval_id: String,
    },
    Approve {
        approval_id: String,
    },
    Deny {
        approval_id: String,
        #[arg(long)]
        reason: String,
    },
}

#[derive(Subcommand, Clone)]
enum ServerCommands {
    /// Call HTTP `/healthz` and `/readyz`
    Health,
    /// Summarize HTTP reachability and related configuration
    Info,
}

#[derive(Subcommand, Clone)]
enum WitnessCommands {
    Inspect { id: String },
    Verify { id: String },
}

#[derive(Clone, Copy, ValueEnum)]
enum PolicyStatusCli {
    Active,
    Inactive,
    Draft,
}

#[derive(Clone, Copy, ValueEnum)]
enum RunStatusCli {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Clone, Copy, ValueEnum)]
enum IncidentStatusCli {
    Open,
    Acknowledged,
    Resolved,
    Dismissed,
}

#[derive(Clone, Copy, ValueEnum)]
enum ApprovalStatusCli {
    Pending,
    Approved,
    Denied,
    Expired,
}

#[derive(Debug, Deserialize)]
struct PolicyRulesFile {
    #[serde(default)]
    default_action: Option<String>,
    rules: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct PolicyEvalFile {
    rules: Vec<agentfirewall_core::PolicyRule>,
    default_action: agentfirewall_core::PolicyDecision,
    #[serde(default)]
    tenant_id: Option<Uuid>,
    #[serde(default)]
    version_id: Option<Uuid>,
}

fn server_url() -> String {
    std::env::var("AV_SERVER_URL").unwrap_or_else(|_| "http://127.0.0.1:50051".into())
}

fn http_base_url() -> String {
    if let Ok(h) = std::env::var("AV_HTTP_URL") {
        return h.trim_end_matches('/').to_string();
    }
    let g = server_url();
    let g = g.trim_end_matches('/');
    if let Some(prefix) = g.strip_suffix(":50051") {
        format!("{prefix}:8080")
    } else {
        "http://127.0.0.1:8080".into()
    }
}

fn tenant_scope() -> Result<ResourceScope> {
    let tid = std::env::var("AV_TENANT_ID").unwrap_or_else(|_| Uuid::nil().to_string());
    Uuid::parse_str(tid.trim()).map_err(|_| {
        anyhow!(
            "AV_TENANT_ID must be a valid UUID (got {:?}). Example: export AV_TENANT_ID=550e8400-e29b-41d4-a716-446655440000",
            std::env::var("AV_TENANT_ID").ok()
        )
    })?;
    Ok(ResourceScope {
        scope_type: ScopeType::Org as i32,
        scope_id: tid,
    })
}

fn map_grpc_error(url: &str, status: tonic::Status) -> anyhow::Error {
    let code: &'static str = match status.code() {
        tonic::Code::Unauthenticated => "AUTH_INVALID_CREDENTIALS",
        tonic::Code::PermissionDenied => "PERMISSION_DENIED",
        tonic::Code::NotFound => "NOT_FOUND",
        tonic::Code::InvalidArgument => "INVALID_ARGUMENT",
        tonic::Code::AlreadyExists | tonic::Code::Aborted => "CONFLICT",
        tonic::Code::FailedPrecondition => "FAILED_PRECONDITION",
        tonic::Code::ResourceExhausted => "RATE_LIMITED",
        tonic::Code::Unavailable => "UNAVAILABLE",
        tonic::Code::DeadlineExceeded => "UNAVAILABLE",
        tonic::Code::Internal | tonic::Code::Unknown | tonic::Code::DataLoss => "INTERNAL_ERROR",
        _ => "INTERNAL_ERROR",
    };
    let message = match status.code() {
        tonic::Code::Unavailable => format!(
            "Cannot reach the Agent FirewallKit gRPC server at {}.\n\
             Check that the control plane is running and AV_SERVER_URL is correct.\n\
             Details: {}",
            url,
            status.message()
        ),
        tonic::Code::DeadlineExceeded => {
            format!("Request to {} timed out: {}", url, status.message())
        }
        _ => format!("gRPC error ({}): {}", status.code(), status.message()),
    };
    AvCliError { code, message }.into()
}

fn json_list_envelope(items: Vec<serde_json::Value>) -> serde_json::Value {
    let total = items.len();
    serde_json::json!({ "items": items, "total": total })
}

fn cli_error_envelope(e: &anyhow::Error) -> serde_json::Value {
    if let Some(a) = e.downcast_ref::<AvCliError>() {
        return serde_json::json!({
            "error": {
                "code": a.code,
                "message": a.message,
            }
        });
    }
    let msg = format!("{e:#}");
    let code = if msg.contains("not found") {
        "NOT_FOUND"
    } else if msg.contains("HTTP request to")
        || msg.contains("cannot reach HTTP API")
        || msg.contains("Failed to open a gRPC connection")
    {
        "UNAVAILABLE"
    } else if msg.contains("AV_TENANT_ID must be a valid UUID")
        || msg.contains("invalid gRPC URL (AV_SERVER_URL)")
        || msg.contains("--severity must be between")
        || msg.contains("unknown mode")
        || msg.contains("unknown default_action")
        || msg.contains("rules JSON in")
        || msg.contains("invalid compiled policy JSON")
        || msg.contains("each rule must be")
        || msg.contains("rule.")
    {
        "INVALID_ARGUMENT"
    } else {
        "INTERNAL_ERROR"
    };
    serde_json::json!({
        "error": {
            "code": code,
            "message": msg,
        }
    })
}

fn print_cli_failure(cli: &Cli, e: &anyhow::Error) {
    if cli.json {
        let payload = cli_error_envelope(e);
        if let Ok(s) = serde_json::to_string(&payload) {
            eprintln!("{s}");
        } else {
            eprintln!(r#"{{"error":{{"code":"INTERNAL_ERROR","message":"failed to serialize error"}}}}"#);
        }
    } else {
        eprintln!("Error: {e:#}");
    }
}

fn fmt_ts(t: &Option<prost_types::Timestamp>) -> String {
    let Some(ts) = t else {
        return "—".into();
    };
    Utc.timestamp_opt(ts.seconds, ts.nanos as u32)
        .single()
        .map(|d| d.to_rfc3339())
        .unwrap_or_else(|| format!("{}.{:09}", ts.seconds, ts.nanos))
}

fn policy_status_label(s: i32) -> &'static str {
    grpc::policy_v1::PolicyStatus::try_from(s)
        .map(|e| match e {
            grpc::policy_v1::PolicyStatus::Draft => "draft",
            grpc::policy_v1::PolicyStatus::Active => "active",
            grpc::policy_v1::PolicyStatus::Archived => "inactive",
            grpc::policy_v1::PolicyStatus::Unspecified => "unspecified",
        })
        .unwrap_or("unknown")
}

fn run_status_label(s: i32) -> &'static str {
    RunStatus::try_from(s)
        .map(|e| match e {
            RunStatus::Pending => "pending",
            RunStatus::Running => "running",
            RunStatus::Completed => "completed",
            RunStatus::Failed => "failed",
            RunStatus::Cancelled => "cancelled",
            RunStatus::Blocked => "blocked",
            RunStatus::Unspecified => "unspecified",
        })
        .unwrap_or("unknown")
}

fn incident_status_label(s: i32) -> &'static str {
    IncidentStatus::try_from(s)
        .map(|e| match e {
            IncidentStatus::Open => "open",
            IncidentStatus::Acknowledged => "acknowledged",
            IncidentStatus::Resolved => "resolved",
            IncidentStatus::Dismissed => "dismissed",
            IncidentStatus::Unspecified => "unspecified",
        })
        .unwrap_or("unknown")
}

fn approval_status_label(s: i32) -> &'static str {
    ApprovalStatus::try_from(s)
        .map(|e| match e {
            ApprovalStatus::Pending => "pending",
            ApprovalStatus::Approved => "approved",
            ApprovalStatus::Rejected => "denied",
            ApprovalStatus::Expired => "expired",
            ApprovalStatus::Cancelled => "cancelled",
            ApprovalStatus::Unspecified => "unspecified",
        })
        .unwrap_or("unknown")
}

fn prost_value_to_json(v: &ProstValue) -> serde_json::Value {
    use prost_types::value::Kind::*;
    match v.kind.as_ref() {
        Some(NullValue(_)) => serde_json::Value::Null,
        Some(BoolValue(b)) => serde_json::Value::Bool(*b),
        Some(NumberValue(n)) => serde_json::Number::from_f64(*n)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        Some(StringValue(s)) => serde_json::Value::String(s.clone()),
        Some(StructValue(s)) => prost_struct_to_json(s),
        Some(ListValue(list)) => serde_json::Value::Array(
            list.values.iter().map(prost_value_to_json).collect(),
        ),
        None => serde_json::Value::Null,
    }
}

fn prost_struct_to_json(s: &Struct) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    for (k, v) in &s.fields {
        m.insert(k.clone(), prost_value_to_json(v));
    }
    serde_json::Value::Object(m)
}

fn witness_inspect_json(a: &Approval) -> serde_json::Value {
    let witness = a.witness.as_ref().map(|w| {
        serde_json::json!({
            "content_hash": w.content_hash,
            "cas_uri": w.cas_uri,
        })
    });
    let payload = a
        .request_payload
        .as_ref()
        .map(prost_struct_to_json)
        .unwrap_or(serde_json::Value::Null);
    serde_json::json!({
        "approval_id": a.approval_id,
        "status": approval_status_label(a.status),
        "run_id": a.run_id,
        "step_index": a.step_index,
        "policy_id": a.policy_id,
        "rule_id": a.rule_id,
        "reason_code": a.reason_code,
        "requested_by": a.requested_by,
        "created_at": a.created_at.as_ref().map(|t| fmt_ts(&Some(*t))),
        "resolved_at": a.resolved_at.as_ref().map(|t| fmt_ts(&Some(*t))),
        "resolved_by": a.resolved_by,
        "resolution_comment": a.resolution_comment,
        "expires_at": a.expires_at.as_ref().map(|t| fmt_ts(&Some(*t))),
        "witness": witness,
        "request_payload": payload,
    })
}

fn json_to_prost_value(v: &serde_json::Value) -> ProstValue {
    ProstValue {
        kind: Some(match v {
            serde_json::Value::Null => Kind::NullValue(0),
            serde_json::Value::Bool(b) => Kind::BoolValue(*b),
            serde_json::Value::Number(n) => {
                Kind::NumberValue(n.as_f64().unwrap_or_else(|| n.as_i64().unwrap_or(0) as f64))
            }
            serde_json::Value::String(s) => Kind::StringValue(s.clone()),
            serde_json::Value::Array(a) => Kind::ListValue(prost_types::ListValue {
                values: a.iter().map(json_to_prost_value).collect(),
            }),
            serde_json::Value::Object(_) => {
                Kind::StructValue(json_to_prost_struct(v).unwrap_or_default())
            }
        }),
    }
}

fn json_to_prost_struct(v: &serde_json::Value) -> Option<Struct> {
    let serde_json::Value::Object(map) = v else {
        return None;
    };
    let mut fields = BTreeMap::new();
    for (k, val) in map {
        fields.insert(k.clone(), json_to_prost_value(val));
    }
    Some(Struct { fields })
}

fn parse_default_policy_action(s: &str) -> Result<i32> {
    match s.to_ascii_lowercase().replace('-', "_").as_str() {
        "allow" => Ok(DefaultPolicyAction::Allow as i32),
        "deny" => Ok(DefaultPolicyAction::Deny as i32),
        "require_approval" | "requireapproval" => Ok(DefaultPolicyAction::RequireApproval as i32),
        "downgrade" => Ok(DefaultPolicyAction::Downgrade as i32),
        "pause" => Ok(DefaultPolicyAction::Pause as i32),
        _ => Err(anyhow!(
            "unknown default_action {s:?}; expected allow | deny | require_approval | downgrade | pause"
        )),
    }
}

fn parse_rule_target_type(v: Option<&serde_json::Value>) -> Result<i32> {
    let Some(x) = v.and_then(|j| j.as_str()) else {
        return Ok(RuleTargetType::Unspecified as i32);
    };
    match x.to_ascii_lowercase().replace('-', "_").as_str() {
        "model" => Ok(RuleTargetType::Model as i32),
        "tool" => Ok(RuleTargetType::Tool as i32),
        "write_action" | "writeaction" | "write" => Ok(RuleTargetType::WriteAction as i32),
        "delegation" => Ok(RuleTargetType::Delegation as i32),
        "budget" => Ok(RuleTargetType::Budget as i32),
        "unspecified" | "" => Ok(RuleTargetType::Unspecified as i32),
        _ => Err(anyhow!("unknown target_type {x:?}")),
    }
}

fn parse_rule_action(v: Option<&serde_json::Value>) -> Result<i32> {
    let Some(x) = v.and_then(|j| j.as_str()) else {
        return Ok(RuleAction::Unspecified as i32);
    };
    match x.to_ascii_lowercase().replace('-', "_").as_str() {
        "allow" => Ok(RuleAction::Allow as i32),
        "deny" => Ok(RuleAction::Deny as i32),
        "require_approval" | "requireapproval" => Ok(RuleAction::RequireApproval as i32),
        "downgrade" => Ok(RuleAction::Downgrade as i32),
        "pause" => Ok(RuleAction::Pause as i32),
        "unspecified" | "" => Ok(RuleAction::Unspecified as i32),
        _ => Err(anyhow!("unknown rule action {x:?}")),
    }
}

fn policy_rule_from_json(v: &serde_json::Value) -> Result<PolicyRule> {
    let o = v
        .as_object()
        .ok_or_else(|| anyhow!("each rule must be a JSON object"))?;
    let rule_id = o
        .get("rule_id")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("rule.rule_id (UUID string) is required"))?
        .to_string();
    let _ = Uuid::parse_str(rule_id.trim()).map_err(|e| anyhow!("rule_id must be a UUID: {e}"))?;
    let priority = o
        .get("priority")
        .and_then(|x| x.as_i64())
        .ok_or_else(|| anyhow!("rule.priority (integer) is required"))? as i32;
    let target_type = parse_rule_target_type(o.get("target_type"))?;
    let target_selector = o
        .get("target_selector")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let conditions = o.get("conditions").and_then(json_to_prost_struct);
    let action = parse_rule_action(o.get("action"))?;
    let action_config = o.get("action_config").and_then(json_to_prost_struct);
    let reason_code = o
        .get("reason_code")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let enabled = o.get("enabled").and_then(|x| x.as_bool()).unwrap_or(true);
    Ok(PolicyRule {
        rule_id,
        priority,
        target_type,
        target_selector,
        conditions,
        action,
        action_config,
        reason_code,
        enabled,
    })
}

fn load_policy_rules_file(path: &Path) -> Result<(i32, Vec<PolicyRule>)> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read rules file {}", path.display()))?;
    let parsed: PolicyRulesFile =
        serde_json::from_str(&raw).map_err(|e| anyhow!("rules JSON in {}: {e}", path.display()))?;
    let default_action = if let Some(ref s) = parsed.default_action {
        parse_default_policy_action(s)?
    } else {
        DefaultPolicyAction::Deny as i32
    };
    let mut rules = Vec::with_capacity(parsed.rules.len());
    for r in &parsed.rules {
        rules.push(policy_rule_from_json(r)?);
    }
    Ok((default_action, rules))
}

fn policy_to_json(p: &Policy) -> serde_json::Value {
    serde_json::json!({
        "policy_id": p.policy_id,
        "version": p.version,
        "status": p.status,
        "name": p.name,
        "description": p.description,
        "default_action": p.default_action,
        "etag": p.etag,
        "rules": p.rules.iter().map(rule_to_json).collect::<Vec<_>>(),
        "created_at": p.created_at.as_ref().map(|t| fmt_ts(&Some(*t))),
        "updated_at": p.updated_at.as_ref().map(|t| fmt_ts(&Some(*t))),
    })
}

fn rule_to_json(r: &PolicyRule) -> serde_json::Value {
    serde_json::json!({
        "rule_id": r.rule_id,
        "priority": r.priority,
        "target_type": r.target_type,
        "target_selector": r.target_selector,
        "action": r.action,
        "reason_code": r.reason_code,
        "enabled": r.enabled,
    })
}

async fn http_check(base: &str, path: &str) -> Result<(reqwest::StatusCode, String)> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
    let url = format!("{base}{path}");
    let resp = client.get(&url).send().await.with_context(|| {
        format!(
            "HTTP request to {url} failed (set AV_HTTP_URL or use AV_SERVER_URL ending with :50051 to derive :8080)"
        )
    })?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    Ok((status, body))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();
    if let Err(e) = run_cli(&cli).await {
        print_cli_failure(&cli, &e);
        std::process::exit(1);
    }
}

async fn run_cli(cli: &Cli) -> Result<()> {
    let url = server_url();

    match cli.command.clone() {
        Some(Commands::Learner(sub)) => {
            let scope = tenant_scope()?;
            let channel = client::connect_channel(&url).await?;
            let interceptor =
                client::metadata_interceptor(cli.api_key.clone(), scope.scope_id.clone());
            let mut client = LearnerServiceClient::with_interceptor(channel, interceptor);
            match sub {
                LearnerCommands::Status => {
                    let res = client
                        .get_mode(GetModeRequest {
                            scope: Some(scope.clone()),
                        })
                        .await
                        .map_err(|e| map_grpc_error(&url, e))?;
                    let inner = res.into_inner();
                    let mode =
                        LearnerMode::try_from(inner.mode).unwrap_or(LearnerMode::Unspecified);
                    if cli.json {
                        println!("{{\"mode\":\"{}\"}}", mode_label(mode).replace('-', "_"));
                    } else {
                        println!("Learner mode: {}", mode_label(mode).green());
                    }
                }
                LearnerCommands::SetMode { mode } => {
                    let m = parse_learner_mode(&mode)?;
                    let _ = client
                        .set_mode(SetModeRequest {
                            idempotency: None,
                            scope: Some(scope.clone()),
                            mode: m as i32,
                            comment: String::new(),
                        })
                        .await
                        .map_err(|e| map_grpc_error(&url, e))?;
                    if cli.json {
                        println!("{{\"ok\":true,\"mode\":\"{}\"}}", mode_label(m));
                    } else {
                        println!("Set learner mode to {}", mode_label(m).green());
                    }
                }
                LearnerCommands::Candidates => {
                    let res = client
                        .list_candidates(ListCandidatesRequest {
                            page: None,
                            scope: Some(scope.clone()),
                            status_filter: CandidateStatus::Proposed as i32,
                        })
                        .await
                        .map_err(|e| map_grpc_error(&url, e))?;
                    let inner = res.into_inner();
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json_list_candidates(&inner))?
                        );
                    } else {
                        let mut table = Table::new();
                        table.load_preset(UTF8_FULL);
                        table.set_header(vec!["candidate_id", "status", "summary"]);
                        for c in inner.candidates {
                            let summary = c
                                .proposed_policy
                                .as_ref()
                                .map(|p| p.name.as_str())
                                .unwrap_or("—");
                            table.add_row(vec![
                                Cell::new(c.candidate_id),
                                Cell::new(format!(
                                    "{:?}",
                                    CandidateStatus::try_from(c.status)
                                        .unwrap_or(CandidateStatus::Unspecified)
                                )),
                                Cell::new(summary),
                            ]);
                        }
                        println!("{table}");
                    }
                }
                LearnerCommands::Approve { id } => {
                    let res = client
                        .approve_candidate(ApproveCandidateRequest {
                            idempotency: None,
                            candidate_id: id.clone(),
                            approved_by: std::env::var("USER").unwrap_or_default(),
                            comment: String::new(),
                            activate_as_draft: false,
                        })
                        .await
                        .map_err(|e| map_grpc_error(&url, e))?;
                    let inner = res.into_inner();
                    if cli.json {
                        println!("{}", serde_json::to_string_pretty(&json_approve(&inner))?);
                    } else {
                        println!(
                            "Approved candidate {} (policy version: {})",
                            id.green(),
                            inner.resulting_policy_id
                        );
                    }
                }
                LearnerCommands::Reject { id, reason } => {
                    let res = client
                        .reject_candidate(RejectCandidateRequest {
                            idempotency: None,
                            candidate_id: id.clone(),
                            rejected_by: std::env::var("USER").unwrap_or_default(),
                            comment: reason,
                        })
                        .await
                        .map_err(|e| map_grpc_error(&url, e))?;
                    let inner = res.into_inner();
                    if cli.json {
                        println!("{}", serde_json::to_string_pretty(&json_reject(&inner))?);
                    } else {
                        println!("Rejected candidate {}", id.yellow());
                    }
                }
                LearnerCommands::Baseline => {
                    let res = client
                        .get_baseline(GetBaselineRequest {
                            scope: Some(scope.clone()),
                        })
                        .await
                        .map_err(|e| map_grpc_error(&url, e))?;
                    let inner = res.into_inner();
                    if cli.json {
                        println!("{}", serde_json::to_string_pretty(&json_baseline(&inner))?);
                    } else {
                        let baseline = inner.baseline.as_ref();
                        let mut table = Table::new();
                        table.load_preset(UTF8_FULL);
                        table.set_header(vec!["signal", "score"]);
                        if let Some(b) = baseline {
                            for s in &b.signals {
                                table.add_row(vec![Cell::new(&s.name), Cell::new(s.score)]);
                            }
                        }
                        println!("{table}");
                    }
                }
            }
        }
        Some(Commands::Policy(sub)) => match sub {
            PolicyCommands::Validate { file } => {
                let raw = std::fs::read_to_string(&file)
                    .with_context(|| format!("read {}", file.display()))?;
                let parsed: PolicyEvalFile = serde_json::from_str(&raw).map_err(|e| {
                        anyhow!(
                            "invalid compiled policy JSON (see agentfirewall-core PolicyRule / PolicyDecision): {e}"
                        )
                    })?;
                let tid = parsed.tenant_id.unwrap_or_else(Uuid::nil);
                let vid = parsed.version_id.unwrap_or_else(Uuid::new_v4);
                let set = CompiledPolicySet::new(parsed.rules, parsed.default_action, vid, tid);
                let mut ev = PolicyEvaluator::new();
                ev.load_policy_set(set);
                let now = Utc::now();
                let ctx = RunContext {
                    tenant_id: tid,
                    run_id: Uuid::new_v4(),
                    agent_id: Uuid::new_v4(),
                    workspace_id: None,
                    project_id: None,
                    policy_version_id: Some(vid),
                    mode: RunMode::Enforce,
                    goal_text: "cli-validate".into(),
                    started_at: now,
                    step_index: 0,
                    budget: BudgetSnapshot {
                        reserved_usd: Default::default(),
                        estimated_usd: Default::default(),
                        actual_usd: Default::default(),
                        limit_usd: rust_decimal::Decimal::new(1_000_000, 2),
                        updated_at: now,
                    },
                    labels: Default::default(),
                    metadata: serde_json::json!({}),
                };
                let probe = ActionDescriptor::simple(ActionType::ToolCall, "cli/validate-probe");
                let decision = ev.evaluate(&ctx, &probe);
                if cli.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": true,
                            "rules_loaded": ev.active_snapshot().map(|s| s.rules.len()).unwrap_or(0),
                            "probe_decision": format!("{decision:?}"),
                        }))?
                    );
                } else {
                    println!(
                        "{}",
                        "Policy JSON is valid and loads into PolicyEvaluator.".green()
                    );
                    println!(
                        "Rules: {}",
                        ev.active_snapshot().map(|s| s.rules.len()).unwrap_or(0)
                    );
                    println!("Probe evaluation: {decision:?}");
                }
            }
            other => {
                let scope = tenant_scope()?;
                let channel = client::connect_channel(&url).await?;
                let interceptor =
                    client::metadata_interceptor(cli.api_key.clone(), scope.scope_id.clone());
                let mut client = PolicyServiceClient::with_interceptor(channel, interceptor);
                match other {
                    PolicyCommands::List { status } => {
                        let status_filter = match status {
                            Some(PolicyStatusCli::Active) => {
                                grpc::policy_v1::PolicyStatus::Active as i32
                            }
                            Some(PolicyStatusCli::Inactive) => {
                                grpc::policy_v1::PolicyStatus::Archived as i32
                            }
                            Some(PolicyStatusCli::Draft) => {
                                grpc::policy_v1::PolicyStatus::Draft as i32
                            }
                            None => grpc::policy_v1::PolicyStatus::Unspecified as i32,
                        };
                        let res = client
                            .list_policies(ListPoliciesRequest {
                                page: Some(PageRequest {
                                    page_cursor: String::new(),
                                    page_size: 200,
                                }),
                                scope: Some(scope.clone()),
                                status_filter,
                                name_prefix: String::new(),
                            })
                            .await
                            .map_err(|e| map_grpc_error(&url, e))?;
                        let inner = res.into_inner();
                        if cli.json {
                            let rows: Vec<serde_json::Value> = inner
                            .policies
                            .iter()
                            .map(|p| {
                                serde_json::json!({
                                    "policy_id": p.policy_id,
                                    "name": p.name,
                                    "status": policy_status_label(p.status),
                                    "version": p.version,
                                    "updated_at": p.updated_at.as_ref().map(|t| fmt_ts(&Some(*t))),
                                })
                            })
                            .collect();
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&json_list_envelope(rows))?
                            );
                        } else {
                            let mut table = Table::new();
                            table.load_preset(UTF8_FULL);
                            table.set_header(vec!["ID", "Name", "Status", "Version", "Updated"]);
                            for p in inner.policies {
                                table.add_row(vec![
                                    Cell::new(&p.policy_id),
                                    Cell::new(&p.name),
                                    Cell::new(policy_status_label(p.status)),
                                    Cell::new(p.version),
                                    Cell::new(fmt_ts(&p.updated_at)),
                                ]);
                            }
                            println!("{table}");
                        }
                    }
                    PolicyCommands::Get { policy_id } => {
                        let res = client
                            .get_policy(GetPolicyRequest {
                                policy_id: policy_id.clone(),
                                version: 0,
                            })
                            .await
                            .map_err(|e| map_grpc_error(&url, e))?;
                        let inner = res.into_inner();
                        let p = inner.policy.ok_or_else(|| anyhow!("policy not found"))?;
                        if cli.json {
                            println!("{}", serde_json::to_string_pretty(&policy_to_json(&p))?);
                        } else {
                            println!("{} {} ({})", "Policy".green(), p.name, p.policy_id);
                            println!(
                                "status: {}  version: {}",
                                policy_status_label(p.status),
                                p.version
                            );
                            println!("updated: {}", fmt_ts(&p.updated_at));
                            println!();
                            let mut table = Table::new();
                            table.load_preset(UTF8_FULL);
                            table.set_header(vec![
                                "rule_id", "prio", "target", "action", "enabled", "reason",
                            ]);
                            for r in &p.rules {
                                table.add_row(vec![
                                    Cell::new(&r.rule_id),
                                    Cell::new(r.priority),
                                    Cell::new(&r.target_selector),
                                    Cell::new(r.action),
                                    Cell::new(r.enabled),
                                    Cell::new(&r.reason_code),
                                ]);
                            }
                            println!("{table}");
                        }
                    }
                    PolicyCommands::Create {
                        name,
                        description,
                        rules,
                    } => {
                        let (default_action, rule_msgs) = load_policy_rules_file(&rules)?;
                        let res = client
                            .create_policy(CreatePolicyRequest {
                                idempotency: None,
                                scope: Some(scope.clone()),
                                name,
                                description,
                                default_action,
                                rules: rule_msgs,
                                labels: None,
                                create_as_draft: true,
                            })
                            .await
                            .map_err(|e| map_grpc_error(&url, e))?;
                        let inner = res.into_inner();
                        let p = inner
                            .policy
                            .ok_or_else(|| anyhow!("create_policy returned empty policy"))?;
                        if cli.json {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&serde_json::json!({
                                    "policy_id": p.policy_id,
                                    "version": p.version,
                                }))?
                            );
                        } else {
                            println!("Created policy {}", p.policy_id.green());
                        }
                    }
                    PolicyCommands::Activate { policy_id } => {
                        let get = client
                            .get_policy(GetPolicyRequest {
                                policy_id: policy_id.clone(),
                                version: 0,
                            })
                            .await
                            .map_err(|e| map_grpc_error(&url, e))?;
                        let etag = get
                            .into_inner()
                            .policy
                            .ok_or_else(|| anyhow!("get_policy returned empty policy"))?
                            .etag;
                        if etag.trim().is_empty() {
                            return Err(anyhow!("policy has no etag; cannot activate"));
                        }
                        let res = client
                            .activate_policy(ActivatePolicyRequest {
                                idempotency: None,
                                policy_id: policy_id.clone(),
                                etag,
                                activation_comment: String::new(),
                            })
                            .await
                            .map_err(|e| map_grpc_error(&url, e))?;
                        let inner = res.into_inner();
                        let p = inner.policy.ok_or_else(|| anyhow!("empty policy"))?;
                        if cli.json {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&serde_json::json!({
                                    "policy_id": p.policy_id,
                                    "status": policy_status_label(p.status),
                                }))?
                            );
                        } else {
                            println!("Activated policy {}", policy_id.green());
                        }
                    }
                    PolicyCommands::Deactivate { policy_id } => {
                        let get = client
                            .get_policy(GetPolicyRequest {
                                policy_id: policy_id.clone(),
                                version: 0,
                            })
                            .await
                            .map_err(|e| map_grpc_error(&url, e))?;
                        let etag = get
                            .into_inner()
                            .policy
                            .ok_or_else(|| anyhow!("get_policy returned empty policy"))?
                            .etag;
                        if etag.trim().is_empty() {
                            return Err(anyhow!("policy has no etag; cannot deactivate"));
                        }
                        let res = client
                            .deactivate_policy(DeactivatePolicyRequest {
                                idempotency: None,
                                policy_id: policy_id.clone(),
                                etag,
                                deactivation_comment: String::new(),
                            })
                            .await
                            .map_err(|e| map_grpc_error(&url, e))?;
                        let inner = res.into_inner();
                        let p = inner.policy.ok_or_else(|| anyhow!("empty policy"))?;
                        if cli.json {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&serde_json::json!({
                                    "policy_id": p.policy_id,
                                    "status": policy_status_label(p.status),
                                }))?
                            );
                        } else {
                            println!("Deactivated policy {}", policy_id.yellow());
                        }
                    }
                    PolicyCommands::Validate { .. } => {
                        unreachable!("policy validate is handled before opening gRPC")
                    }
                }
            }
        },
        Some(Commands::Run(sub)) => {
            let scope = tenant_scope()?;
            let channel = client::connect_channel(&url).await?;
            let interceptor =
                client::metadata_interceptor(cli.api_key.clone(), scope.scope_id.clone());
            let mut client = RunServiceClient::with_interceptor(channel, interceptor);
            match sub {
                RunCommands::List { status } => {
                    let status_filter = match status {
                        Some(RunStatusCli::Pending) => RunStatus::Pending as i32,
                        Some(RunStatusCli::Running) => RunStatus::Running as i32,
                        Some(RunStatusCli::Completed) => RunStatus::Completed as i32,
                        Some(RunStatusCli::Failed) => RunStatus::Failed as i32,
                        Some(RunStatusCli::Cancelled) => RunStatus::Cancelled as i32,
                        None => RunStatus::Unspecified as i32,
                    };
                    let res = client
                        .list_runs(ListRunsRequest {
                            page: Some(PageRequest {
                                page_cursor: String::new(),
                                page_size: 200,
                            }),
                            scope: Some(scope.clone()),
                            status_filter,
                            agent_id: String::new(),
                        })
                        .await
                        .map_err(|e| map_grpc_error(&url, e))?;
                    let inner = res.into_inner();
                    if cli.json {
                        let rows: Vec<serde_json::Value> = inner
                            .runs
                            .iter()
                            .map(|r| {
                                serde_json::json!({
                                    "run_id": r.run_id,
                                    "status": run_status_label(r.status),
                                    "step_index": r.step_index,
                                    "agent_id": r.agent_id,
                                    "mode": r.mode,
                                    "goal": r.goal,
                                })
                            })
                            .collect();
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json_list_envelope(rows))?
                        );
                    } else {
                        let mut table = Table::new();
                        table.load_preset(UTF8_FULL);
                        table.set_header(vec!["run_id", "status", "step", "agent", "mode"]);
                        for r in inner.runs {
                            table.add_row(vec![
                                Cell::new(r.run_id),
                                Cell::new(run_status_label(r.status)),
                                Cell::new(r.step_index),
                                Cell::new(r.agent_id),
                                Cell::new(&r.mode),
                            ]);
                        }
                        println!("{table}");
                    }
                }
                RunCommands::Get { run_id } => {
                    let res = client
                        .get_run(GetRunRequest {
                            run_id: run_id.clone(),
                        })
                        .await
                        .map_err(|e| map_grpc_error(&url, e))?;
                    let inner = res.into_inner();
                    let r = inner.run.ok_or_else(|| anyhow!("run not found"))?;
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "run_id": r.run_id,
                                "status": run_status_label(r.status),
                                "step_index": r.step_index,
                                "agent_id": r.agent_id,
                                "mode": r.mode,
                                "goal": r.goal,
                                "budget": r.budget.as_ref().map(|b| b.components.len()),
                            }))?
                        );
                    } else {
                        println!("Run {}", r.run_id.green());
                        println!(
                            "status: {}  step: {}  agent: {}",
                            run_status_label(r.status),
                            r.step_index,
                            r.agent_id
                        );
                        println!("mode: {}  goal: {}", r.mode, r.goal);
                        if let Some(b) = r.budget.as_ref() {
                            println!("budget components: {}", b.components.len());
                            let mut t = Table::new();
                            t.load_preset(UTF8_FULL);
                            t.set_header(vec!["unit", "reserved", "consumed", "limit"]);
                            for c in &b.components {
                                t.add_row(vec![
                                    Cell::new(c.unit),
                                    Cell::new(c.reserved),
                                    Cell::new(c.consumed),
                                    Cell::new(c.limit),
                                ]);
                            }
                            println!("{t}");
                        }
                    }
                }
                RunCommands::Cancel { run_id } => {
                    let res = client
                        .cancel_run(CancelRunRequest {
                            idempotency: None,
                            run_id: run_id.clone(),
                            reason_code: "cli_cancel".into(),
                            comment: String::new(),
                        })
                        .await
                        .map_err(|e| map_grpc_error(&url, e))?;
                    let inner = res.into_inner();
                    let r = inner.run.ok_or_else(|| anyhow!("empty run"))?;
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "run_id": r.run_id,
                                "status": run_status_label(r.status),
                            }))?
                        );
                    } else {
                        println!(
                            "Cancelled run {} → {}",
                            run_id.yellow(),
                            run_status_label(r.status)
                        );
                    }
                }
            }
        }
        Some(Commands::Incident(sub)) => {
            let scope = tenant_scope()?;
            let channel = client::connect_channel(&url).await?;
            let interceptor =
                client::metadata_interceptor(cli.api_key.clone(), scope.scope_id.clone());
            let mut client = IncidentServiceClient::with_interceptor(channel, interceptor);
            match sub {
                IncidentCommands::List { status, severity } => {
                    if let Some(s) = severity {
                        if !(1..=5).contains(&s) {
                            return Err(anyhow!("--severity must be between 1 and 5"));
                        }
                    }
                    let status_filter = match status {
                        Some(IncidentStatusCli::Open) => IncidentStatus::Open as i32,
                        Some(IncidentStatusCli::Acknowledged) => {
                            IncidentStatus::Acknowledged as i32
                        }
                        Some(IncidentStatusCli::Resolved) => IncidentStatus::Resolved as i32,
                        Some(IncidentStatusCli::Dismissed) => IncidentStatus::Dismissed as i32,
                        None => IncidentStatus::Unspecified as i32,
                    };
                    let severity_at_least = match severity {
                        Some(1) => IncidentSeverity::Info as i32,
                        Some(2) => IncidentSeverity::Low as i32,
                        Some(3) => IncidentSeverity::Medium as i32,
                        Some(4) => IncidentSeverity::High as i32,
                        Some(5) => IncidentSeverity::Critical as i32,
                        None => IncidentSeverity::Unspecified as i32,
                        _ => unreachable!(),
                    };
                    let res = client
                        .list_incidents(ListIncidentsRequest {
                            page: Some(PageRequest {
                                page_cursor: String::new(),
                                page_size: 200,
                            }),
                            scope: Some(scope.clone()),
                            status_filter,
                            severity_at_least,
                            reason_code_prefix: String::new(),
                        })
                        .await
                        .map_err(|e| map_grpc_error(&url, e))?;
                    let inner = res.into_inner();
                    if cli.json {
                        let rows: Vec<serde_json::Value> = inner
                            .incidents
                            .iter()
                            .map(|i| {
                                serde_json::json!({
                                    "incident_id": i.incident_id,
                                    "title": i.title,
                                    "status": incident_status_label(i.status),
                                    "severity": i.severity,
                                    "run_id": i.run_id,
                                })
                            })
                            .collect();
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json_list_envelope(rows))?
                        );
                    } else {
                        let mut table = Table::new();
                        table.load_preset(UTF8_FULL);
                        table.set_header(vec!["id", "severity", "status", "title", "run_id"]);
                        for i in inner.incidents {
                            table.add_row(vec![
                                Cell::new(i.incident_id),
                                Cell::new(i.severity),
                                Cell::new(incident_status_label(i.status)),
                                Cell::new(i.title),
                                Cell::new(i.run_id),
                            ]);
                        }
                        println!("{table}");
                    }
                }
                IncidentCommands::Get { incident_id } => {
                    let res = client
                        .get_incident(GetIncidentRequest {
                            incident_id: incident_id.clone(),
                        })
                        .await
                        .map_err(|e| map_grpc_error(&url, e))?;
                    let inner = res.into_inner();
                    let i = inner
                        .incident
                        .ok_or_else(|| anyhow!("incident not found"))?;
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "incident_id": i.incident_id,
                                "title": i.title,
                                "summary": i.summary,
                                "status": incident_status_label(i.status),
                                "severity": i.severity,
                                "run_id": i.run_id,
                                "policy_id": i.policy_id,
                            }))?
                        );
                    } else {
                        println!("{} {}", "Incident".green(), i.incident_id);
                        println!("{} [{}]", i.title, incident_status_label(i.status));
                        println!("severity: {}\n{}", i.severity, i.summary);
                    }
                }
                IncidentCommands::Ack { incident_id } => {
                    let res = client
                        .acknowledge_incident(AcknowledgeIncidentRequest {
                            idempotency: None,
                            incident_id: incident_id.clone(),
                            acknowledged_by: std::env::var("USER").unwrap_or_default(),
                            comment: String::new(),
                        })
                        .await
                        .map_err(|e| map_grpc_error(&url, e))?;
                    let inner = res.into_inner();
                    let i = inner.incident.ok_or_else(|| anyhow!("empty incident"))?;
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "incident_id": i.incident_id,
                                "status": incident_status_label(i.status),
                            }))?
                        );
                    } else {
                        println!("Acknowledged {}", incident_id.green());
                    }
                }
                IncidentCommands::Resolve { incident_id, note } => {
                    let res = client
                        .resolve_incident(ResolveIncidentRequest {
                            idempotency: None,
                            incident_id: incident_id.clone(),
                            resolved_by: std::env::var("USER").unwrap_or_default(),
                            resolution_summary: note,
                            resolution_metadata: None,
                        })
                        .await
                        .map_err(|e| map_grpc_error(&url, e))?;
                    let inner = res.into_inner();
                    let i = inner.incident.ok_or_else(|| anyhow!("empty incident"))?;
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "incident_id": i.incident_id,
                                "status": incident_status_label(i.status),
                            }))?
                        );
                    } else {
                        println!("Resolved {}", incident_id.green());
                    }
                }
            }
        }
        Some(Commands::Approval(sub)) => {
            let scope = tenant_scope()?;
            let channel = client::connect_channel(&url).await?;
            let interceptor =
                client::metadata_interceptor(cli.api_key.clone(), scope.scope_id.clone());
            let mut client = ApprovalServiceClient::with_interceptor(channel, interceptor);
            match sub {
                ApprovalCommands::List { status } => {
                    let status_filter = match status {
                        Some(ApprovalStatusCli::Pending) => ApprovalStatus::Pending as i32,
                        Some(ApprovalStatusCli::Approved) => ApprovalStatus::Approved as i32,
                        Some(ApprovalStatusCli::Denied) => ApprovalStatus::Rejected as i32,
                        Some(ApprovalStatusCli::Expired) => ApprovalStatus::Expired as i32,
                        None => ApprovalStatus::Unspecified as i32,
                    };
                    let res = client
                        .list_approvals(ListApprovalsRequest {
                            page: Some(PageRequest {
                                page_cursor: String::new(),
                                page_size: 200,
                            }),
                            run_id: String::new(),
                            status_filter,
                        })
                        .await
                        .map_err(|e| map_grpc_error(&url, e))?;
                    let inner = res.into_inner();
                    if cli.json {
                        let rows: Vec<serde_json::Value> = inner
                            .approvals
                            .iter()
                            .map(|a| {
                                serde_json::json!({
                                    "approval_id": a.approval_id,
                                    "status": approval_status_label(a.status),
                                    "run_id": a.run_id,
                                    "step_index": a.step_index,
                                    "reason_code": a.reason_code,
                                })
                            })
                            .collect();
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json_list_envelope(rows))?
                        );
                    } else {
                        let mut table = Table::new();
                        table.load_preset(UTF8_FULL);
                        table.set_header(vec!["approval_id", "status", "run", "step", "reason"]);
                        for a in inner.approvals {
                            table.add_row(vec![
                                Cell::new(a.approval_id),
                                Cell::new(approval_status_label(a.status)),
                                Cell::new(a.run_id),
                                Cell::new(a.step_index),
                                Cell::new(a.reason_code),
                            ]);
                        }
                        println!("{table}");
                    }
                }
                ApprovalCommands::Get { approval_id } => {
                    let res = client
                        .get_approval(GetApprovalRequest {
                            approval_id: approval_id.clone(),
                        })
                        .await
                        .map_err(|e| map_grpc_error(&url, e))?;
                    let inner = res.into_inner();
                    let a = inner
                        .approval
                        .ok_or_else(|| anyhow!("approval not found"))?;
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "approval_id": a.approval_id,
                                "status": approval_status_label(a.status),
                                "run_id": a.run_id,
                                "step_index": a.step_index,
                                "policy_id": a.policy_id,
                                "rule_id": a.rule_id,
                                "reason_code": a.reason_code,
                            }))?
                        );
                    } else {
                        println!("Approval {}", a.approval_id.green());
                        println!(
                            "status: {}  run: {} step {}",
                            approval_status_label(a.status),
                            a.run_id,
                            a.step_index
                        );
                    }
                }
                ApprovalCommands::Approve { approval_id } => {
                    let res = client
                        .resolve_approval(ResolveApprovalRequest {
                            idempotency: None,
                            approval_id: approval_id.clone(),
                            resolution: ApprovalStatus::Approved as i32,
                            resolved_by: std::env::var("USER").unwrap_or_default(),
                            resolution_comment: String::new(),
                        })
                        .await
                        .map_err(|e| map_grpc_error(&url, e))?;
                    let inner = res.into_inner();
                    let a = inner.approval.ok_or_else(|| anyhow!("empty approval"))?;
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "approval_id": a.approval_id,
                                "status": approval_status_label(a.status),
                            }))?
                        );
                    } else {
                        println!("Approved {}", approval_id.green());
                    }
                }
                ApprovalCommands::Deny {
                    approval_id,
                    reason,
                } => {
                    let res = client
                        .resolve_approval(ResolveApprovalRequest {
                            idempotency: None,
                            approval_id: approval_id.clone(),
                            resolution: ApprovalStatus::Rejected as i32,
                            resolved_by: std::env::var("USER").unwrap_or_default(),
                            resolution_comment: reason,
                        })
                        .await
                        .map_err(|e| map_grpc_error(&url, e))?;
                    let inner = res.into_inner();
                    let a = inner.approval.ok_or_else(|| anyhow!("empty approval"))?;
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "approval_id": a.approval_id,
                                "status": approval_status_label(a.status),
                            }))?
                        );
                    } else {
                        println!("Denied {}", approval_id.yellow());
                    }
                }
            }
        }
        Some(Commands::Server(sub)) => {
            let base = http_base_url();
            match sub {
                ServerCommands::Health => {
                    let (hz, hz_body) = http_check(&base, "/healthz")
                        .await
                        .with_context(|| format!("cannot reach HTTP API at {base}"))?;
                    let (rz, rz_body) = http_check(&base, "/readyz")
                        .await
                        .with_context(|| format!("cannot reach HTTP API at {base}"))?;
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "http_base": base,
                                "healthz": { "status": hz.as_u16(), "body": hz_body },
                                "readyz": { "status": rz.as_u16(), "body": rz_body },
                            }))?
                        );
                    } else {
                        println!("HTTP base: {}", base.cyan());
                        println!(
                            "  /healthz → {} ({})",
                            hz.as_str(),
                            if hz.is_success() {
                                "live".green()
                            } else {
                                "not ok".red()
                            }
                        );
                        println!(
                            "  /readyz  → {} ({})",
                            rz.as_str(),
                            if rz.is_success() {
                                "postgres/redis/nats reachable".green()
                            } else {
                                "one or more dependencies unhealthy".red()
                            }
                        );
                    }
                }
                ServerCommands::Info => {
                    let hz = http_check(&base, "/healthz").await;
                    let rz = http_check(&base, "/readyz").await;
                    let hz_ok = hz
                        .as_ref()
                        .ok()
                        .map(|(s, _)| s.is_success())
                        .unwrap_or(false);
                    let rz_ok = rz
                        .as_ref()
                        .ok()
                        .map(|(s, _)| s.is_success())
                        .unwrap_or(false);
                    let grpc = server_url();
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "cli_version": env!("CARGO_PKG_VERSION"),
                                "grpc_url": grpc,
                                "http_base": base,
                                "healthz_ok": hz_ok,
                                "readyz_ok": rz_ok,
                                "note": "Server process version and uptime are not exposed on these HTTP endpoints in this build.",
                            }))?
                        );
                    } else {
                        println!("Agent FirewallKit CLI v{}", env!("CARGO_PKG_VERSION"));
                        println!("gRPC URL (AV_SERVER_URL): {}", grpc.cyan());
                        println!("HTTP base (AV_HTTP_URL or derived): {}", base.cyan());
                        println!(
                            "healthz: {}  readyz: {}",
                            if hz_ok { "ok".green() } else { "fail".red() },
                            if rz_ok { "ok".green() } else { "fail".red() },
                        );
                        if hz.is_err() || rz.is_err() {
                            println!(
                                "{}",
                                "An HTTP check failed to connect; verify AV_HTTP_URL.".yellow()
                            );
                        }
                        println!(
                            "Connected services: when readyz is OK, PostgreSQL, Redis, and NATS are reachable."
                        );
                        println!(
                            "Server binary version and uptime are not published on /healthz in this release."
                        );
                    }
                }
            }
        }
        Some(Commands::Witness(sub)) => {
            let scope = tenant_scope()?;
            let channel = client::connect_channel(&url).await?;
            let interceptor =
                client::metadata_interceptor(cli.api_key.clone(), scope.scope_id.clone());
            let mut client = ApprovalServiceClient::with_interceptor(channel, interceptor);
            match sub {
                WitnessCommands::Inspect { id } => {
                    let res = client
                        .get_approval(GetApprovalRequest {
                            approval_id: id.clone(),
                        })
                        .await
                        .map_err(|e| map_grpc_error(&url, e))?;
                    let inner = res.into_inner();
                    let a = inner
                        .approval
                        .ok_or_else(|| anyhow!("approval not found"))?;
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&witness_inspect_json(&a))?
                        );
                    } else {
                        println!("{} {}", "Witness".green(), id.cyan());
                        if let Some(w) = a.witness.as_ref() {
                            println!("content_hash: {}", w.content_hash);
                            if !w.cas_uri.is_empty() {
                                println!("cas_uri:      {}", w.cas_uri);
                            }
                        } else {
                            println!("{}", "no witness bundle on this approval".yellow());
                        }
                        println!(
                            "approval: {}  run: {}  step {}",
                            approval_status_label(a.status),
                            a.run_id,
                            a.step_index
                        );
                    }
                }
                WitnessCommands::Verify { id } => {
                    let get = client
                        .get_approval(GetApprovalRequest {
                            approval_id: id.clone(),
                        })
                        .await
                        .map_err(|e| map_grpc_error(&url, e))?;
                    let a = get
                        .into_inner()
                        .approval
                        .ok_or_else(|| anyhow!("approval not found"))?;
                    let w = a
                        .witness
                        .as_ref()
                        .ok_or_else(|| anyhow!("approval has no witness bundle to verify"))?;
                    if w.content_hash.trim().is_empty() {
                        return Err(anyhow!("approval witness has empty content_hash"));
                    }
                    let rev = client
                        .revalidate_approval(RevalidateApprovalRequest {
                            idempotency: None,
                            approval_id: id.clone(),
                            witness: Some(WitnessBundle {
                                content_hash: w.content_hash.clone(),
                                cas_uri: w.cas_uri.clone(),
                            }),
                            revalidation_context: None,
                        })
                        .await
                        .map_err(|e| map_grpc_error(&url, e))?;
                    let inner = rev.into_inner();
                    if cli.json {
                        let appr = inner.approval.as_ref();
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "approval_id": id,
                                "witness_valid": inner.witness_valid,
                                "reason_code": inner.reason_code,
                                "status": appr.map(|x| approval_status_label(x.status)),
                            }))?
                        );
                    } else {
                        let label = if inner.witness_valid {
                            "valid".green()
                        } else {
                            "invalid".red()
                        };
                        println!("Witness hash for approval {} → {}", id.cyan(), label);
                        if !inner.reason_code.is_empty() {
                            println!("reason_code: {}", inner.reason_code);
                        }
                    }
                }
            }
        }
        None => {
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "cli_version": env!("CARGO_PKG_VERSION"),
                        "message": "No subcommand given; use --help for usage.",
                    }))?
                );
            } else {
                println!("Agent FirewallKit CLI v{}", env!("CARGO_PKG_VERSION"));
                println!("Try: agentfirewall learner --help");
            }
        }
    }

    Ok(())
}

fn parse_learner_mode(s: &str) -> Result<LearnerMode> {
    match s.to_ascii_lowercase().replace('_', "-").as_str() {
        "observe-only" | "observeonly" => Ok(LearnerMode::ObserveOnly),
        "recommend" => Ok(LearnerMode::Recommend),
        "auto-promote-safe" | "autopromotesafe" => Ok(LearnerMode::AutoPromoteSafe),
        _ => Err(anyhow!(
            "unknown mode {:?}; expected observe-only | recommend | auto-promote-safe",
            s
        )),
    }
}

fn json_list_candidates(inner: &grpc::learner_v1::ListCandidatesResponse) -> serde_json::Value {
    let items: Vec<serde_json::Value> = inner
        .candidates
        .iter()
        .map(|c| {
            serde_json::json!({
                "candidate_id": c.candidate_id,
                "status": c.status,
                "confidence": c.confidence,
                "policy_name": c.proposed_policy.as_ref().map(|p| p.name.as_str()),
            })
        })
        .collect();
    json_list_envelope(items)
}

fn json_baseline(inner: &grpc::learner_v1::GetBaselineResponse) -> serde_json::Value {
    let baseline = inner.baseline.as_ref();
    let signals: Vec<serde_json::Value> = baseline
        .map(|b| {
            b.signals
                .iter()
                .map(|s| serde_json::json!({ "name": s.name, "score": s.score }))
                .collect()
        })
        .unwrap_or_default();
    serde_json::json!({ "signals": signals })
}

fn json_approve(inner: &grpc::learner_v1::ApproveCandidateResponse) -> serde_json::Value {
    serde_json::json!({
        "resulting_policy_id": inner.resulting_policy_id,
        "candidate_id": inner.candidate.as_ref().map(|c| c.candidate_id.as_str()),
    })
}

fn json_reject(inner: &grpc::learner_v1::RejectCandidateResponse) -> serde_json::Value {
    serde_json::json!({
        "candidate_id": inner.candidate.as_ref().map(|c| c.candidate_id.as_str()),
    })
}

fn mode_label(m: LearnerMode) -> &'static str {
    match m {
        LearnerMode::ObserveOnly => "observe-only",
        LearnerMode::Recommend => "recommend",
        LearnerMode::AutoPromoteSafe => "auto-promote-safe",
        LearnerMode::Unspecified => "unspecified",
    }
}
