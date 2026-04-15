//! Per-run lifecycle, step history, and budget accounting.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::error::AgentFirewallError;
use crate::types::{ActionDescriptor, BudgetSnapshot, PolicyDecision, RunContext, RunMode};

/// Configuration used to start a new guarded run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunConfig {
    pub tenant_id: Uuid,
    pub run_id: Uuid,
    pub agent_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<Uuid>,
    pub mode: RunMode,
    pub goal_text: String,
    pub budget_limit_usd: Decimal,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(default)]
    pub metadata: Value,
}

impl RunConfig {
    fn into_initial_context(self) -> RunContext {
        let now = Utc::now();
        RunContext {
            tenant_id: self.tenant_id,
            run_id: self.run_id,
            agent_id: self.agent_id,
            workspace_id: self.workspace_id,
            project_id: self.project_id,
            policy_version_id: None,
            mode: self.mode,
            goal_text: self.goal_text,
            started_at: now,
            step_index: 0,
            budget: BudgetSnapshot {
                reserved_usd: Decimal::ZERO,
                estimated_usd: Decimal::ZERO,
                actual_usd: Decimal::ZERO,
                limit_usd: self.budget_limit_usd,
                updated_at: now,
            },
            labels: self.labels,
            metadata: self.metadata,
        }
    }
}

/// Immutable record of a completed step for audit and replay.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StepRecord {
    pub step_index: u32,
    pub action: ActionDescriptor,
    pub decision: PolicyDecision,
    pub cost_actual: Option<Decimal>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug)]
struct RunState {
    context: RunContext,
    step_history: Vec<StepRecord>,
    is_terminal: bool,
}

/// Thread-safe manager for a single run's mutable state.
#[derive(Debug, Clone)]
pub struct RunContextManager {
    inner: Arc<RwLock<RunState>>,
}

impl RunContextManager {
    pub fn new(config: RunConfig) -> Self {
        let ctx = config.into_initial_context();
        Self {
            inner: Arc::new(RwLock::new(RunState {
                context: ctx,
                step_history: Vec::new(),
                is_terminal: false,
            })),
        }
    }

    pub fn context(&self) -> RunContext {
        self.inner.read().context.clone()
    }

    pub fn current_step(&self) -> u32 {
        self.inner.read().context.step_index
    }

    /// Increments the active step counter and returns the new step index.
    pub fn advance_step(&self) -> u32 {
        let mut g = self.inner.write();
        g.context.step_index = g
            .context
            .step_index
            .checked_add(1)
            .expect("step_index overflow");
        g.context.step_index
    }

    pub fn record_step(
        &self,
        action: ActionDescriptor,
        decision: PolicyDecision,
        cost: Option<Decimal>,
    ) {
        let mut g = self.inner.write();
        let idx = g.context.step_index;
        g.step_history.push(StepRecord {
            step_index: idx,
            action,
            decision,
            cost_actual: cost,
            timestamp: Utc::now(),
        });
    }

    pub fn update_budget(&self, cost: Decimal) -> Result<(), AgentFirewallError> {
        if cost < Decimal::ZERO {
            return Err(AgentFirewallError::ConfigInvalid(format!(
                "negative budget increment: {cost}"
            )));
        }
        if cost.is_zero() {
            return Ok(());
        }

        let mut g = self.inner.write();
        let new_actual = g
            .context
            .budget
            .actual_usd
            .checked_add(cost)
            .ok_or_else(|| {
                AgentFirewallError::ConfigInvalid("decimal overflow while accumulating budget".into())
            })?;

        if new_actual > g.context.budget.limit_usd {
            return Err(AgentFirewallError::BudgetExceeded {
                limit: g.context.budget.limit_usd,
                actual: new_actual,
            });
        }

        g.context.budget.actual_usd = new_actual;
        g.context.budget.updated_at = Utc::now();
        Ok(())
    }

    pub fn budget_remaining(&self) -> Decimal {
        let g = self.inner.read();
        (g.context.budget.limit_usd - g.context.budget.actual_usd).max(Decimal::ZERO)
    }

    pub fn is_budget_exceeded(&self) -> bool {
        let g = self.inner.read();
        g.context.budget.actual_usd >= g.context.budget.limit_usd
    }

    pub fn mark_terminal(&self) {
        self.inner.write().is_terminal = true;
    }

    pub fn is_terminal(&self) -> bool {
        self.inner.read().is_terminal
    }

    pub fn step_history(&self) -> Vec<StepRecord> {
        self.inner.read().step_history.clone()
    }

    pub fn elapsed(&self) -> Duration {
        let g = self.inner.read();
        (Utc::now() - g.context.started_at)
            .to_std()
            .unwrap_or(Duration::ZERO)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ActionType, ReasonCode};
    use serde_json::json;
    use std::thread;

    fn sample_config(limit: Decimal) -> RunConfig {
        RunConfig {
            tenant_id: Uuid::new_v4(),
            run_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            workspace_id: None,
            project_id: None,
            mode: RunMode::Enforce,
            goal_text: "do the thing".into(),
            budget_limit_usd: limit,
            labels: HashMap::from([("env".into(), "test".into())]),
            metadata: json!({ "k": 1 }),
        }
    }

    #[test]
    fn new_run_starts_at_step_zero_with_budget() {
        let m = RunContextManager::new(sample_config(Decimal::from_str_exact("10").unwrap()));
        assert_eq!(m.current_step(), 0);
        assert_eq!(m.budget_remaining(), Decimal::from_str_exact("10").unwrap());
        assert!(!m.is_budget_exceeded());
        let c = m.context();
        assert_eq!(c.goal_text, "do the thing");
        assert_eq!(c.labels.get("env").map(String::as_str), Some("test"));
    }

    #[test]
    fn advance_and_record_step() {
        let m = RunContextManager::new(sample_config(Decimal::from(100)));
        assert_eq!(m.advance_step(), 1);
        m.record_step(
            ActionDescriptor::simple(ActionType::ToolCall, "ls"),
            PolicyDecision::Allow {
                reason_code: ReasonCode::new("OK"),
            },
            Some(Decimal::from_str_exact("0.01").unwrap()),
        );
        let h = m.step_history();
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].step_index, 1);
        assert_eq!(m.current_step(), 1);
    }

    #[test]
    fn update_budget_atomic_and_remaining() {
        let m = RunContextManager::new(sample_config(Decimal::from_str_exact("5").unwrap()));
        m.update_budget(Decimal::from_str_exact("2").unwrap())
            .unwrap();
        assert_eq!(m.budget_remaining(), Decimal::from_str_exact("3").unwrap());
        m.update_budget(Decimal::from_str_exact("3").unwrap())
            .unwrap();
        assert!(m.is_budget_exceeded());
        let err = m
            .update_budget(Decimal::from_str_exact("0.01").unwrap())
            .unwrap_err();
        assert!(matches!(err, AgentFirewallError::BudgetExceeded { .. }));
    }

    #[test]
    fn negative_cost_rejected() {
        let m = RunContextManager::new(sample_config(Decimal::ONE));
        let e = m.update_budget(Decimal::from_str_exact("-1").unwrap());
        assert!(e.is_err());
    }

    #[test]
    fn terminal_flag() {
        let m = RunContextManager::new(sample_config(Decimal::ONE));
        assert!(!m.is_terminal());
        m.mark_terminal();
        assert!(m.is_terminal());
    }

    #[test]
    fn concurrent_budget_updates_serializable() {
        let m = RunContextManager::new(sample_config(Decimal::from(1000)));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let mm = m.clone();
                thread::spawn(move || {
                    for _ in 0..50 {
                        mm.update_budget(Decimal::ONE).ok();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let actual = m.context().budget.actual_usd;
        assert!(actual <= Decimal::from(1000));
    }
}
