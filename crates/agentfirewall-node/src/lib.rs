//! NAPI-RS bindings for Agent FirewallKit (Node.js / TypeScript).
#![allow(clippy::new_without_default, clippy::field_reassign_with_default)]

use std::collections::HashMap;
use std::sync::Mutex;

use agentfirewall_core::reason::{
    ReasonCodeRegistry as CoreReasonRegistry, ReasonEntry, ReasonFamily, Severity,
};
use agentfirewall_core::types::{
    ActionDescriptor, ActionType, BudgetSnapshot as CoreBudgetSnapshot, LearnerMode,
    PolicyDecision as CorePolicyDecision, ReasonCode, RunContext, SpanEvent, WitnessHash,
    WitnessResult,
};
use agentfirewall_core::{
    CompiledPolicySet, PolicyEvaluator as CorePolicyEvaluator, PolicyRule, RunConfig,
};
use agentfirewall_embed::DEFAULT_EMBEDDING_MODEL_ID;
use agentfirewall_learner::{
    LearnerClient as InnerLearnerClient, LearnerClientConfig as InnerLearnerConfig,
};
use agentfirewall_sentinel::SentinelConfig;
use agentfirewall_witness::capture::StateSnapshot as CoreStateSnapshot;
use agentfirewall_witness::guard::WitnessGuard as CoreWitnessGuard;
use agentfirewall_witness::revalidation::RevalidationOutcome as CoreRevalidationOutcome;
use agentfirewall_witness::WitnessError;
use chrono::{DateTime, Utc};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use serde_json::{json, Value};
use uuid::Uuid;

fn av_err(e: agentfirewall_core::AgentFirewallError) -> Error {
    Error::from_reason(e.to_string())
}

fn learner_err(e: agentfirewall_learner::LearnerError) -> Error {
    Error::from_reason(e.to_string())
}

fn witness_err(e: WitnessError) -> Error {
    Error::from_reason(e.to_string())
}

fn hex_hash(h: &WitnessHash) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in h.as_bytes() {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

fn parse_witness_hash_hex(raw: &str) -> Result<WitnessHash> {
    let s = raw.trim().trim_start_matches("0x");
    if s.len() != 64 {
        return Err(Error::from_reason(format!(
            "witness hash must be 64 hex chars, got length {}",
            s.len()
        )));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|e| Error::from_reason(format!("invalid witness hash hex: {e}")))?;
        out[i] = byte;
    }
    Ok(WitnessHash(out))
}

fn f64_to_decimal(amount: f64) -> Result<Decimal> {
    Decimal::from_f64_retain(amount)
        .ok_or_else(|| Error::from_reason(format!("invalid amount: {amount}")))
}

fn parse_action_type(raw: &str) -> Result<ActionType> {
    match raw.trim() {
        "tool_call" => Ok(ActionType::ToolCall),
        "model_call" => Ok(ActionType::ModelCall),
        "write" => Ok(ActionType::Write),
        "delegation" => Ok(ActionType::Delegation),
        s if s.starts_with("custom:") => Ok(ActionType::Custom(s["custom:".len()..].to_string())),
        other => Err(Error::from_reason(format!(
            "unknown actionType '{other}'; use tool_call, model_call, write, delegation, or custom:<name>"
        ))),
    }
}

fn policy_decision_to_view(d: CorePolicyDecision) -> PolicyDecisionDto {
    let (decision, reason_code, detail) = match d {
        CorePolicyDecision::Allow { reason_code } => {
            ("allow", Some(reason_code.to_string()), None::<Value>)
        }
        CorePolicyDecision::Deny {
            reason_code,
            detail: det,
        } => ("deny", Some(reason_code.to_string()), det),
        CorePolicyDecision::Downgrade {
            reason_code,
            action_config,
        } => (
            "downgrade",
            Some(reason_code.to_string()),
            Some(json!({ "action_config": action_config })),
        ),
        CorePolicyDecision::Pause {
            reason_code,
            wait_timeout_ms,
        } => (
            "pause",
            Some(reason_code.to_string()),
            Some(json!({ "wait_timeout_ms": wait_timeout_ms })),
        ),
        CorePolicyDecision::RequireApproval {
            reason_code,
            witness_required,
        } => (
            "require_approval",
            Some(reason_code.to_string()),
            Some(json!({ "witness_required": witness_required })),
        ),
    };
    PolicyDecisionDto {
        decision: decision.to_string(),
        reason_code,
        detail,
    }
}

fn parse_learner_mode(raw: &str) -> Result<LearnerMode> {
    match raw.trim() {
        "observe_only" => Ok(LearnerMode::ObserveOnly),
        "recommend" => Ok(LearnerMode::Recommend),
        "auto_promote_safe" => Ok(LearnerMode::AutoPromoteSafe),
        other => Err(Error::from_reason(format!(
            "invalid learner mode '{other}'; expected observe_only, recommend, or auto_promote_safe"
        ))),
    }
}

fn learner_mode_to_string(m: LearnerMode) -> String {
    match m {
        LearnerMode::ObserveOnly => "observe_only".into(),
        LearnerMode::Recommend => "recommend".into(),
        LearnerMode::AutoPromoteSafe => "auto_promote_safe".into(),
    }
}

// --- Exported types (NAPI object names match TypeScript) ---

#[napi(object, js_name = "PolicyDecision")]
#[derive(Clone)]
pub struct PolicyDecisionDto {
    pub decision: String,
    pub reason_code: Option<String>,
    pub detail: Option<Value>,
}

#[napi(object)]
pub struct BudgetSnapshot {
    /// Total budget limit (alias for `limit_usd`).
    pub total_usd: f64,
    pub spent_usd: f64,
    pub remaining_usd: f64,
    pub reserved_usd: f64,
    pub estimated_usd: f64,
    pub limit_usd: f64,
    pub updated_at: String,
}

impl From<&CoreBudgetSnapshot> for BudgetSnapshot {
    fn from(b: &CoreBudgetSnapshot) -> Self {
        let limit = b.limit_usd.to_f64().unwrap_or(0.0);
        let actual = b.actual_usd.to_f64().unwrap_or(0.0);
        let reserved = b.reserved_usd.to_f64().unwrap_or(0.0);
        let estimated = b.estimated_usd.to_f64().unwrap_or(0.0);
        let remaining = (b.limit_usd - b.actual_usd).max(Decimal::ZERO);
        let remaining_f = remaining.to_f64().unwrap_or(0.0);
        BudgetSnapshot {
            total_usd: limit,
            spent_usd: actual,
            remaining_usd: remaining_f,
            reserved_usd: reserved,
            estimated_usd: estimated,
            limit_usd: limit,
            updated_at: b.updated_at.to_rfc3339(),
        }
    }
}

#[napi(object)]
pub struct StateSnapshot {
    pub hash: String,
    pub resource_uri: String,
    pub captured_at: String,
    pub format_version: u8,
    pub size_bytes: u32,
    pub preimage: Uint8Array,
}

impl TryFrom<&StateSnapshot> for CoreStateSnapshot {
    type Error = Error;

    fn try_from(s: &StateSnapshot) -> std::result::Result<Self, Self::Error> {
        let preimage: Vec<u8> = s.preimage.to_vec();
        let captured_at = DateTime::parse_from_rfc3339(&s.captured_at)
            .map_err(|e| Error::from_reason(format!("captured_at: {e}")))?
            .with_timezone(&Utc);
        let hash = parse_witness_hash_hex(&s.hash)?;
        Ok(CoreStateSnapshot {
            preimage,
            hash,
            format_version: s.format_version,
            captured_at,
            resource_uri: s.resource_uri.clone(),
            size_bytes: s.size_bytes as usize,
        })
    }
}

fn core_snapshot_to_js(s: &CoreStateSnapshot) -> StateSnapshot {
    StateSnapshot {
        hash: hex_hash(&s.hash),
        resource_uri: s.resource_uri.clone(),
        captured_at: s.captured_at.to_rfc3339(),
        format_version: s.format_version,
        size_bytes: s.size_bytes as u32,
        preimage: Uint8Array::from(s.preimage.as_slice()),
    }
}

#[napi(object)]
pub struct RevalidationOutcome {
    pub result: String,
    pub original_hash: String,
    pub current_hash: String,
}

fn revalidation_to_js(o: &CoreRevalidationOutcome) -> RevalidationOutcome {
    let result = match &o.result {
        WitnessResult::Valid => "valid",
        WitnessResult::StateChanged { .. } => "state_changed",
    };
    RevalidationOutcome {
        result: result.to_string(),
        original_hash: hex_hash(&o.original_hash),
        current_hash: hex_hash(&o.current_hash),
    }
}

#[napi(object)]
pub struct LearnerClientConfig {
    pub nats_url: String,
    pub tenant_id: String,
    pub subject_prefix: Option<String>,
    pub sample_rate: Option<f64>,
    pub publish_queue_capacity: Option<u32>,
    pub max_span_bytes: Option<u32>,
}

impl From<LearnerClientConfig> for InnerLearnerConfig {
    fn from(c: LearnerClientConfig) -> Self {
        let mut base = InnerLearnerConfig::default();
        base.nats_url = c.nats_url;
        base.tenant_id = c.tenant_id;
        if let Some(p) = c.subject_prefix {
            base.subject_prefix = p;
        }
        if let Some(r) = c.sample_rate {
            base.sample_rate = r as f32;
        }
        if let Some(cap) = c.publish_queue_capacity {
            base.publish_queue_capacity = cap as usize;
        }
        if let Some(m) = c.max_span_bytes {
            base.max_span_bytes = m as usize;
        }
        base
    }
}

#[napi(object)]
pub struct SentinelConfigView {
    pub enabled: bool,
    pub model_id: String,
    pub stall_threshold: f64,
    pub stall_window: u32,
    pub regression_threshold: f64,
    pub max_intervention: String,
    pub max_embed_input_bytes: u32,
    pub ema_alpha: f64,
}

impl From<SentinelConfigView> for SentinelConfig {
    fn from(v: SentinelConfigView) -> Self {
        let max_intervention = match v.max_intervention.to_ascii_lowercase().as_str() {
            "warn" => agentfirewall_core::InterventionLevel::Warn,
            "downgrade" => agentfirewall_core::InterventionLevel::Downgrade,
            "pause" => agentfirewall_core::InterventionLevel::Pause,
            "deny" => agentfirewall_core::InterventionLevel::Deny,
            _ => agentfirewall_core::InterventionLevel::Warn,
        };
        SentinelConfig {
            enabled: v.enabled,
            model_id: v.model_id,
            stall_threshold: v.stall_threshold as f32,
            stall_window: v.stall_window,
            regression_threshold: v.regression_threshold as f32,
            max_intervention,
            max_embed_input_bytes: v.max_embed_input_bytes as usize,
            ema_alpha: v.ema_alpha as f32,
        }
    }
}

impl From<SentinelConfig> for SentinelConfigView {
    fn from(c: SentinelConfig) -> Self {
        let max_intervention = match c.max_intervention {
            agentfirewall_core::InterventionLevel::Warn => "warn",
            agentfirewall_core::InterventionLevel::Downgrade => "downgrade",
            agentfirewall_core::InterventionLevel::Pause => "pause",
            agentfirewall_core::InterventionLevel::Deny => "deny",
        }
        .to_string();
        SentinelConfigView {
            enabled: c.enabled,
            model_id: c.model_id,
            stall_threshold: f64::from(c.stall_threshold),
            stall_window: c.stall_window,
            regression_threshold: f64::from(c.regression_threshold),
            max_intervention,
            max_embed_input_bytes: c.max_embed_input_bytes as u32,
            ema_alpha: f64::from(c.ema_alpha),
        }
    }
}

// --- Classes ---

#[napi(js_name = "PolicyEvaluator")]
pub struct PolicyEvaluatorJs {
    inner: Mutex<CorePolicyEvaluator>,
}

#[napi]
impl PolicyEvaluatorJs {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(CorePolicyEvaluator::new()),
        }
    }

    #[napi]
    pub fn load_rules_json(&self, rules: String) -> Result<()> {
        let set: CompiledPolicySet = serde_json::from_str(&rules)
            .map_err(|e| Error::from_reason(format!("invalid policy JSON: {e}")))?;
        self.inner
            .lock()
            .map_err(|e| Error::from_reason(e.to_string()))?
            .load_policy_set(set);
        Ok(())
    }

    #[napi]
    pub fn add_rule_json(&self, rule_json: String) -> Result<()> {
        let rule: PolicyRule = serde_json::from_str(&rule_json)
            .map_err(|e| Error::from_reason(format!("invalid rule JSON: {e}")))?;
        self.inner
            .lock()
            .map_err(|e| Error::from_reason(e.to_string()))?
            .append_rule(rule)
            .map_err(av_err)?;
        Ok(())
    }

    #[napi]
    pub fn evaluate(
        &self,
        action_type: String,
        resource: String,
        context: Value,
    ) -> Result<PolicyDecisionDto> {
        let ctx: RunContext = serde_json::from_value(context)
            .map_err(|e| Error::from_reason(format!("invalid run context: {e}")))?;
        let action = ActionDescriptor {
            action_type: parse_action_type(&action_type)?,
            resource,
            cost_estimate_usd: None,
            metadata: HashMap::new(),
        };
        let inner = self
            .inner
            .lock()
            .map_err(|e| Error::from_reason(e.to_string()))?;
        let d = inner.evaluate(&ctx, &action);
        Ok(policy_decision_to_view(d))
    }
}

#[napi(js_name = "RunContextManager")]
pub struct RunContextManagerJs {
    inner: agentfirewall_core::RunContextManager,
}

#[napi]
impl RunContextManagerJs {
    #[napi(constructor)]
    pub fn new(run_id: String, tenant_id: String, goal: String) -> Result<Self> {
        let run_id = Uuid::parse_str(run_id.trim())
            .map_err(|e| Error::from_reason(format!("runId: {e}")))?;
        let tenant_id = Uuid::parse_str(tenant_id.trim())
            .map_err(|e| Error::from_reason(format!("tenantId: {e}")))?;
        let budget_limit = Decimal::from(1_000_000u64);
        let config = RunConfig {
            tenant_id,
            run_id,
            agent_id: Uuid::new_v4(),
            workspace_id: None,
            project_id: None,
            mode: agentfirewall_core::RunMode::Enforce,
            goal_text: goal,
            budget_limit_usd: budget_limit,
            labels: HashMap::new(),
            metadata: Value::Null,
        };
        Ok(Self {
            inner: agentfirewall_core::RunContextManager::new(config),
        })
    }

    #[napi]
    pub fn start(&self) -> Result<()> {
        Ok(())
    }

    #[napi]
    pub fn record_cost(&self, amount: f64, unit: String) -> Result<()> {
        let u = unit.to_ascii_lowercase();
        if u != "usd" {
            return Err(Error::from_reason(format!(
                "unsupported cost unit '{unit}'; only 'usd' is supported"
            )));
        }
        let dec = f64_to_decimal(amount)?;
        self.inner.update_budget(dec).map_err(av_err)?;
        Ok(())
    }

    #[napi]
    pub fn record_step(&self, step_id: String, tool: String) -> Result<()> {
        self.inner.advance_step();
        let mut meta = HashMap::new();
        meta.insert("step_id".into(), json!(step_id));
        let action = ActionDescriptor {
            action_type: ActionType::ToolCall,
            resource: tool,
            cost_estimate_usd: None,
            metadata: meta,
        };
        self.inner.record_step(
            action,
            CorePolicyDecision::Allow {
                reason_code: ReasonCode::new("STEP_RECORDED"),
            },
            None,
        );
        Ok(())
    }

    #[napi]
    pub fn get_budget(&self) -> BudgetSnapshot {
        BudgetSnapshot::from(&self.inner.context().budget)
    }

    #[napi]
    pub fn get_context(&self) -> Result<Value> {
        serde_json::to_value(self.inner.context())
            .map_err(|e| Error::from_reason(format!("context serialization: {e}")))
    }
}

#[napi(js_name = "ReasonCodeRegistry")]
pub struct ReasonCodeRegistryJs {
    inner: Mutex<CoreReasonRegistry>,
}

#[napi]
impl ReasonCodeRegistryJs {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(CoreReasonRegistry::new()),
        }
    }

    #[napi]
    pub fn register(&self, code: String, description: String) -> Result<()> {
        let entry = ReasonEntry {
            code: ReasonCode::new(code),
            family: ReasonFamily::System,
            human_message: description,
            severity: Severity::Info,
        };
        self.inner
            .lock()
            .map_err(|e| Error::from_reason(e.to_string()))?
            .register(entry)
            .map_err(av_err)?;
        Ok(())
    }

    #[napi]
    pub fn lookup(&self, code: String) -> Option<String> {
        let reg = self.inner.lock().ok()?;
        let rc = ReasonCode::new(code);
        reg.lookup(&rc).map(|e| e.human_message.clone())
    }
}

#[napi(js_name = "WitnessGuard")]
pub struct WitnessGuardJs {
    inner: CoreWitnessGuard,
}

#[napi]
impl WitnessGuardJs {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: CoreWitnessGuard::new(),
        }
    }

    #[napi]
    pub fn capture_json(&self, value: String, uri: String) -> Result<StateSnapshot> {
        let v: Value = serde_json::from_str(&value)
            .map_err(|e| Error::from_reason(format!("value must be JSON: {e}")))?;
        let snap = self
            .inner
            .capture_json_for_approval(&v, &uri)
            .map_err(witness_err)?;
        Ok(core_snapshot_to_js(&snap))
    }

    #[napi]
    pub fn verify_json(
        &self,
        snapshot: StateSnapshot,
        current: String,
    ) -> Result<RevalidationOutcome> {
        let core_snap = CoreStateSnapshot::try_from(&snapshot)?;
        let v: Value = serde_json::from_str(&current)
            .map_err(|e| Error::from_reason(format!("current must be JSON: {e}")))?;
        let out = self
            .inner
            .verify_json_before_execution(&core_snap, &v)
            .map_err(witness_err)?;
        Ok(revalidation_to_js(&out))
    }
}

#[napi(js_name = "LearnerClient")]
pub struct LearnerClientJs {
    inner: InnerLearnerClient,
}

#[napi]
impl LearnerClientJs {
    #[napi(constructor)]
    pub fn new(config: LearnerClientConfig) -> Result<Self> {
        let inner = InnerLearnerClient::new(config.into()).map_err(learner_err)?;
        Ok(Self { inner })
    }

    #[napi]
    pub async fn connect(&self) -> Result<()> {
        self.inner.connect().await.map_err(learner_err)
    }

    #[napi]
    pub fn emit_span(&self, span: Value) -> Result<()> {
        let ev: SpanEvent = serde_json::from_value(span)
            .map_err(|e| Error::from_reason(format!("invalid span: {e}")))?;
        self.inner.emit_span(ev).map_err(learner_err)?;
        Ok(())
    }

    #[napi]
    pub fn get_mode(&self) -> Result<String> {
        Ok(learner_mode_to_string(self.inner.mode()))
    }

    #[napi]
    pub fn set_mode(&self, mode: String) -> Result<String> {
        let m = parse_learner_mode(&mode)?;
        let prev = self.inner.set_mode(m).map_err(learner_err)?;
        Ok(learner_mode_to_string(prev))
    }

    #[napi]
    pub async fn shutdown(&self) -> Result<()> {
        self.inner.shutdown().await.map_err(learner_err)
    }
}

/// Config-only Sentinel handle (no embedding in Node); use [`sentinel_validate`] after building.
#[napi(js_name = "SentinelConfigHolder")]
pub struct SentinelConfigHolderJs {
    inner: SentinelConfig,
}

#[napi]
impl SentinelConfigHolderJs {
    #[napi(constructor)]
    pub fn from_view(config: SentinelConfigView) -> Self {
        Self {
            inner: SentinelConfig::from(config),
        }
    }

    #[napi]
    pub fn validate(&self) -> Result<()> {
        self.inner
            .validate()
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn to_object(&self) -> SentinelConfigView {
        SentinelConfigView::from(self.inner.clone())
    }
}

#[napi(js_name = "sentinelDefaultConfig")]
pub fn sentinel_default_config() -> SentinelConfigView {
    SentinelConfigView::from(SentinelConfig::default())
}

#[napi(js_name = "defaultEmbeddingModelId")]
pub fn default_embedding_model_id() -> String {
    DEFAULT_EMBEDDING_MODEL_ID.to_string()
}
