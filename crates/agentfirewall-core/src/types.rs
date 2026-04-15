//! Core domain types for the Agent FirewallKit control plane.

use std::collections::HashMap;
use std::fmt;

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// Machine-oriented reason identifier (for example `POLICY_HIGH_IMPACT_WRITE`).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReasonCode(String);

impl ReasonCode {
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for ReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ReasonCode").field(&self.0).finish()
    }
}

impl fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for ReasonCode {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for ReasonCode {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

/// Enforcement disposition produced by policy evaluation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow {
        reason_code: ReasonCode,
    },
    Deny {
        reason_code: ReasonCode,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<Value>,
    },
    Downgrade {
        reason_code: ReasonCode,
        action_config: Value,
    },
    Pause {
        reason_code: ReasonCode,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        wait_timeout_ms: Option<u64>,
    },
    RequireApproval {
        reason_code: ReasonCode,
        witness_required: bool,
    },
}

/// How tightly the control plane constrains agent behavior for a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunMode {
    Monitor,
    Enforce,
    Standalone,
}

/// Point-in-time budget figures attached to a run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BudgetSnapshot {
    pub reserved_usd: Decimal,
    pub estimated_usd: Decimal,
    pub actual_usd: Decimal,
    pub limit_usd: Decimal,
    pub updated_at: DateTime<Utc>,
}

/// Identity and runtime context for an agent run under a tenant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunContext {
    pub tenant_id: Uuid,
    pub run_id: Uuid,
    pub agent_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version_id: Option<Uuid>,
    pub mode: RunMode,
    pub goal_text: String,
    pub started_at: DateTime<Utc>,
    pub step_index: u32,
    pub budget: BudgetSnapshot,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    pub metadata: Value,
}

/// How strongly the sentinel should intervene when a condition fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterventionLevel {
    Warn,
    Downgrade,
    Pause,
    Deny,
}

/// Embedding-based progress telemetry for a single observation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProgressSnapshot {
    pub run_id: Uuid,
    pub step_index: u64,
    pub similarity: f32,
    pub delta: f32,
    pub ema_similarity: f32,
    pub ema_delta: f32,
    pub consecutive_stalls: u32,
    pub embedding_model_revision: String,
    pub observed_at: DateTime<Utc>,
}

/// Cryptographic fingerprint of approved state (32-byte digest).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WitnessHash(pub [u8; 32]);

impl WitnessHash {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for WitnessHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WitnessHash({})", hex_lower_32(&self.0))
    }
}

/// Outcome of comparing live state against an approval witness.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WitnessResult {
    Valid,
    StateChanged {
        expected: WitnessHash,
        current: WitnessHash,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        changed_fields: Option<Vec<String>>,
    },
}

/// Types that can serialize their preimage for witness hashing.
pub trait StateCapture {
    type Error: std::error::Error + Send + Sync + 'static;

    fn capture_witness_preimage(&self) -> Result<Vec<u8>, Self::Error>;
}

/// How aggressively the learner may change policy recommendations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LearnerMode {
    ObserveOnly,
    Recommend,
    AutoPromoteSafe,
}

/// Internal span envelope (maps to wire `SpanIngestEvent`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpanEvent {
    pub event_id: Uuid,
    pub trace_id: String,
    pub span_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<String>,
    pub ts: DateTime<Utc>,
    pub tenant_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<Uuid>,
    pub agent_type: String,
    pub agent_id: Uuid,
    pub task_category: String,
    pub run_id: Uuid,
    pub kind: String,
    pub tool_name: String,
    pub tool_args_fingerprint: String,
    pub model_id: String,
    pub cost_usd: f64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub step_index: u32,
    pub progress_score: f32,
    pub progress_delta: f32,
    pub write_target_uri: String,
    pub write_operation: String,
    pub net_host: String,
    pub net_method: String,
    #[serde(default)]
    pub attributes: HashMap<String, String>,
    pub sdk_version: String,
}

/// Aggregated behavioral statistics for an agent type on a calendar day.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BehavioralBaseline {
    pub bucket_date: NaiveDate,
    pub tenant_id: Uuid,
    pub agent_type: String,
    pub baseline_version: u32,
    pub tool_entropy: f32,
    pub top_tools: Vec<String>,
    pub loop_rate: f32,
    pub avg_cost_per_run: f32,
    pub sample_runs: u64,
    pub updated_at: DateTime<Utc>,
    /// Mean tool-call count per run (rolling window used for training).
    #[serde(default)]
    pub avg_tool_calls: f64,
    #[serde(default)]
    pub stddev_tool_calls: f64,
    #[serde(default)]
    pub avg_model_calls: f64,
    #[serde(default)]
    pub stddev_model_calls: f64,
    #[serde(default)]
    pub stddev_cost: f64,
    #[serde(default)]
    pub avg_duration_ms: f64,
    #[serde(default)]
    pub stddev_duration_ms: f64,
}

/// High-level category of an action evaluated by policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    ToolCall,
    ModelCall,
    Write,
    Delegation,
    Custom(String),
}

/// Action under evaluation, including optional cost and structured metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionDescriptor {
    pub action_type: ActionType,
    pub resource: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_estimate_usd: Option<Decimal>,
    #[serde(default)]
    pub metadata: HashMap<String, Value>,
}

impl ActionDescriptor {
    #[must_use]
    pub fn simple(action_type: ActionType, resource: impl Into<String>) -> Self {
        Self {
            action_type,
            resource: resource.into(),
            cost_estimate_usd: None,
            metadata: HashMap::new(),
        }
    }
}

fn hex_lower_32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn sample_budget() -> BudgetSnapshot {
        BudgetSnapshot {
            reserved_usd: Decimal::new(100, 2),
            estimated_usd: Decimal::ZERO,
            actual_usd: Decimal::ZERO,
            limit_usd: Decimal::new(5000, 2),
            updated_at: Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap(),
        }
    }

    fn sample_run_context() -> RunContext {
        RunContext {
            tenant_id: Uuid::nil(),
            run_id: Uuid::nil(),
            agent_id: Uuid::nil(),
            workspace_id: None,
            project_id: None,
            policy_version_id: None,
            mode: RunMode::Enforce,
            goal_text: String::new(),
            started_at: Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap(),
            step_index: 0,
            budget: sample_budget(),
            labels: HashMap::new(),
            metadata: Value::Null,
        }
    }

    #[test]
    fn reason_code_display_and_empty() {
        let c = ReasonCode::new("");
        assert_eq!(c.to_string(), "");
        assert_eq!(format!("{c}"), "");
        let c2 = ReasonCode::new("POLICY_DENY");
        assert_eq!(c2.to_string(), "POLICY_DENY");
    }

    #[test]
    fn reason_code_serde_roundtrip() {
        let c = ReasonCode::new("X_Y_Z");
        let j = serde_json::to_string(&c).unwrap();
        assert_eq!(j, "\"X_Y_Z\"");
        let back: ReasonCode = serde_json::from_str(&j).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn policy_decision_serde_roundtrip_variants() {
        let cases = vec![
            PolicyDecision::Allow {
                reason_code: ReasonCode::new("ok"),
            },
            PolicyDecision::Deny {
                reason_code: ReasonCode::new("no"),
                detail: None,
            },
            PolicyDecision::Deny {
                reason_code: ReasonCode::new("no"),
                detail: Some(Value::String("x".into())),
            },
            PolicyDecision::Downgrade {
                reason_code: ReasonCode::new("d"),
                action_config: serde_json::json!({ "cap": 1 }),
            },
            PolicyDecision::Pause {
                reason_code: ReasonCode::new("p"),
                wait_timeout_ms: None,
            },
            PolicyDecision::Pause {
                reason_code: ReasonCode::new("p"),
                wait_timeout_ms: Some(0),
            },
            PolicyDecision::RequireApproval {
                reason_code: ReasonCode::new("a"),
                witness_required: false,
            },
        ];
        for d in cases {
            let j = serde_json::to_value(&d).unwrap();
            let back: PolicyDecision = serde_json::from_value(j).unwrap();
            assert_eq!(back, d);
        }
    }

    #[test]
    fn run_mode_serde_snake_case() {
        let j = serde_json::to_string(&RunMode::Standalone).unwrap();
        assert_eq!(j, "\"standalone\"");
        let m: RunMode = serde_json::from_str("\"monitor\"").unwrap();
        assert_eq!(m, RunMode::Monitor);
    }

    #[test]
    fn intervention_level_and_learner_mode_serde() {
        for level in [
            InterventionLevel::Warn,
            InterventionLevel::Downgrade,
            InterventionLevel::Pause,
            InterventionLevel::Deny,
        ] {
            let v = serde_json::to_value(level).unwrap();
            let back: InterventionLevel = serde_json::from_value(v).unwrap();
            assert_eq!(back, level);
        }
        for mode in [
            LearnerMode::ObserveOnly,
            LearnerMode::Recommend,
            LearnerMode::AutoPromoteSafe,
        ] {
            let v = serde_json::to_value(mode).unwrap();
            let back: LearnerMode = serde_json::from_value(v).unwrap();
            assert_eq!(back, mode);
        }
    }

    #[test]
    fn budget_zero_decimals_roundtrip() {
        let b = BudgetSnapshot {
            reserved_usd: Decimal::ZERO,
            estimated_usd: Decimal::ZERO,
            actual_usd: Decimal::ZERO,
            limit_usd: Decimal::ZERO,
            updated_at: Utc::now(),
        };
        let j = serde_json::to_string(&b).unwrap();
        let back: BudgetSnapshot = serde_json::from_str(&j).unwrap();
        assert_eq!(back.reserved_usd, Decimal::ZERO);
        assert_eq!(back, b);
    }

    #[test]
    fn run_context_roundtrip_empty_goal_and_labels() {
        let ctx = sample_run_context();
        let j = serde_json::to_value(&ctx).unwrap();
        let back: RunContext = serde_json::from_value(j).unwrap();
        assert_eq!(back.goal_text, "");
        assert!(back.labels.is_empty());
        assert_eq!(back, ctx);
    }

    #[test]
    fn witness_hash_debug_is_hex() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xab;
        bytes[31] = 0x0f;
        let h = WitnessHash(bytes);
        let dbg = format!("{h:?}");
        assert!(dbg.starts_with("WitnessHash("));
        assert!(dbg.contains("ab"));
        assert!(dbg.ends_with(')'));
    }

    #[test]
    fn witness_result_serde() {
        let w = WitnessResult::Valid;
        let j = serde_json::to_value(&w).unwrap();
        let back: WitnessResult = serde_json::from_value(j).unwrap();
        assert_eq!(back, w);

        let w2 = WitnessResult::StateChanged {
            expected: WitnessHash([1; 32]),
            current: WitnessHash([2; 32]),
            changed_fields: Some(vec![]),
        };
        let j2 = serde_json::to_value(&w2).unwrap();
        let back2: WitnessResult = serde_json::from_value(j2).unwrap();
        assert_eq!(back2, w2);
    }

    #[test]
    fn action_type_custom_and_units_roundtrip() {
        let types = vec![
            ActionType::ToolCall,
            ActionType::ModelCall,
            ActionType::Write,
            ActionType::Delegation,
            ActionType::Custom(String::new()),
            ActionType::Custom("weird/tool".into()),
        ];
        for a in types {
            let j = serde_json::to_value(&a).unwrap();
            let back: ActionType = serde_json::from_value(j).unwrap();
            assert_eq!(back, a);
        }
    }

    #[test]
    fn span_event_empty_strings_roundtrip() {
        let ev = SpanEvent {
            event_id: Uuid::nil(),
            trace_id: String::new(),
            span_id: String::new(),
            parent_span_id: Some(String::new()),
            ts: Utc::now(),
            tenant_id: Uuid::nil(),
            workspace_id: None,
            project_id: None,
            agent_type: String::new(),
            agent_id: Uuid::nil(),
            task_category: String::new(),
            run_id: Uuid::nil(),
            kind: String::new(),
            tool_name: String::new(),
            tool_args_fingerprint: String::new(),
            model_id: String::new(),
            cost_usd: 0.0,
            input_tokens: 0,
            output_tokens: 0,
            step_index: 0,
            progress_score: 0.0,
            progress_delta: 0.0,
            write_target_uri: String::new(),
            write_operation: String::new(),
            net_host: String::new(),
            net_method: String::new(),
            attributes: HashMap::new(),
            sdk_version: String::new(),
        };
        let j = serde_json::to_value(&ev).unwrap();
        let back: SpanEvent = serde_json::from_value(j).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn behavioral_baseline_roundtrip() {
        let b = BehavioralBaseline {
            bucket_date: NaiveDate::from_ymd_opt(2026, 4, 5).unwrap(),
            tenant_id: Uuid::nil(),
            agent_type: "coder".into(),
            baseline_version: 1,
            tool_entropy: 0.0,
            top_tools: vec![],
            loop_rate: 0.0,
            avg_cost_per_run: 0.0,
            sample_runs: 0,
            updated_at: Utc::now(),
            avg_tool_calls: 0.0,
            stddev_tool_calls: 0.0,
            avg_model_calls: 0.0,
            stddev_model_calls: 0.0,
            stddev_cost: 0.0,
            avg_duration_ms: 0.0,
            stddev_duration_ms: 0.0,
        };
        let j = serde_json::to_value(&b).unwrap();
        let back: BehavioralBaseline = serde_json::from_value(j).unwrap();
        assert_eq!(back, b);
    }

    #[test]
    fn progress_snapshot_large_indices_roundtrip() {
        let p = ProgressSnapshot {
            run_id: Uuid::nil(),
            step_index: u64::MAX,
            similarity: 0.0,
            delta: -0.0,
            ema_similarity: 1.0,
            ema_delta: -1.0,
            consecutive_stalls: u32::MAX,
            embedding_model_revision: String::new(),
            observed_at: Utc::now(),
        };
        let j = serde_json::to_value(&p).unwrap();
        let back: ProgressSnapshot = serde_json::from_value(j).unwrap();
        assert_eq!(back, p);
    }

    struct BytesState(&'static [u8]);

    impl StateCapture for BytesState {
        type Error = std::io::Error;

        fn capture_witness_preimage(&self) -> Result<Vec<u8>, Self::Error> {
            Ok(self.0.to_vec())
        }
    }

    #[test]
    fn state_capture_trait() {
        let s = BytesState(b"hello");
        assert_eq!(s.capture_witness_preimage().unwrap(), b"hello");
    }
}
