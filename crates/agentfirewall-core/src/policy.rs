//! Compiled policy sets and hot-path policy evaluation.

use std::sync::Arc;

use parking_lot::RwLock;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AgentFirewallError;
use crate::types::{
    ActionDescriptor, ActionType, BudgetSnapshot, PolicyDecision, ReasonCode, RunContext,
};

/// A single rule in a compiled policy set.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub name: String,
    /// Lower numeric value = evaluated first.
    pub priority: u32,
    pub condition: RuleCondition,
    /// Outcome when the condition matches (warn-style outcomes use `PolicyDecision::Allow` + reason codes).
    pub action: PolicyDecision,
    pub enabled: bool,
}

/// Boolean expression over run context and action for rule matching.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RuleCondition {
    Always,
    ActionTypeMatch(Vec<ActionType>),
    /// Glob-style match: `prefix*`, `*suffix`, `*`, or exact string against `ActionDescriptor::resource`.
    ResourcePattern(String),
    CostAbove(Decimal),
    BudgetRemainingBelow(Decimal),
    And(Vec<RuleCondition>),
    Or(Vec<RuleCondition>),
    Not(Box<RuleCondition>),
}

/// Sorted, tenant-scoped policy ready for evaluation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompiledPolicySet {
    pub rules: Vec<PolicyRule>,
    pub default_action: PolicyDecision,
    pub version_id: Uuid,
    pub tenant_id: Uuid,
}

impl CompiledPolicySet {
    /// Builds a policy set with rules ordered by ascending `priority` (lower = first).
    pub fn new(
        mut rules: Vec<PolicyRule>,
        default_action: PolicyDecision,
        version_id: Uuid,
        tenant_id: Uuid,
    ) -> Self {
        rules.sort_by_key(|r| r.priority);
        Self {
            rules,
            default_action,
            version_id,
            tenant_id,
        }
    }
}

/// In-process policy evaluator (hot path). Holds the active [`CompiledPolicySet`] behind a cheap `Arc` swap.
#[derive(Debug)]
pub struct PolicyEvaluator {
    active: RwLock<Option<Arc<CompiledPolicySet>>>,
}

impl Default for PolicyEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEvaluator {
    pub fn new() -> Self {
        Self {
            active: RwLock::new(None),
        }
    }

    pub fn load_policy_set(&mut self, policy_set: CompiledPolicySet) {
        *self.active.write() = Some(Arc::new(policy_set));
    }

    pub fn hot_reload(&mut self, new_set: CompiledPolicySet) {
        *self.active.write() = Some(Arc::new(new_set));
    }

    pub fn current_version(&self) -> Option<Uuid> {
        self.active.read().as_ref().map(|s| s.version_id)
    }

    #[must_use]
    pub fn active_snapshot(&self) -> Option<CompiledPolicySet> {
        self.active.read().as_ref().map(|s| (**s).clone())
    }

    /// Evaluates rules in priority order; first match wins. Uninitialized evaluator denies closed.
    pub fn evaluate(&self, context: &RunContext, action: &ActionDescriptor) -> PolicyDecision {
        let set = match self.active.read().clone() {
            Some(s) => s,
            None => {
                return PolicyDecision::Deny {
                    reason_code: ReasonCode::new("POLICY_EVALUATOR_UNINITIALIZED"),
                    detail: None,
                };
            }
        };

        if context.tenant_id != set.tenant_id {
            return PolicyDecision::Deny {
                reason_code: ReasonCode::new("POLICY_TENANT_MISMATCH"),
                detail: None,
            };
        }

        for rule in &set.rules {
            if !rule.enabled {
                continue;
            }
            if condition_matches(&rule.condition, context, action) {
                // Warn-style outcomes are represented upstream as `Allow` + advisory reason codes.
                return rule.action.clone();
            }
        }

        set.default_action.clone()
    }

    /// Appends a rule to the active policy set and re-sorts by priority. Fails if nothing is loaded.
    pub fn append_rule(&mut self, rule: PolicyRule) -> Result<(), AgentFirewallError> {
        let mut set = self
            .active_snapshot()
            .ok_or_else(|| AgentFirewallError::config("policy evaluator has no loaded policy set"))?;
        set.rules.push(rule);
        set.rules.sort_by_key(|r| r.priority);
        self.load_policy_set(set);
        Ok(())
    }
}

fn budget_remaining(snapshot: &BudgetSnapshot) -> Decimal {
    snapshot.limit_usd - snapshot.actual_usd
}

fn resource_matches(pattern: &str, resource: Option<&str>) -> bool {
    let Some(res) = resource.filter(|s| !s.is_empty()) else {
        return pattern.is_empty();
    };

    match pattern {
        "*" => true,
        p if p.ends_with('*') && p.starts_with('*') && p.len() > 1 => {
            let inner = &p[1..p.len() - 1];
            !inner.is_empty() && res.contains(inner)
        }
        p if p.ends_with('*') => {
            let prefix = &p[..p.len() - 1];
            res.starts_with(prefix)
        }
        p if p.starts_with('*') => {
            let suffix = &p[1..];
            res.ends_with(suffix)
        }
        p => res == p,
    }
}

fn resource_field(resource: &str) -> Option<&str> {
    if resource.is_empty() {
        None
    } else {
        Some(resource)
    }
}

fn condition_matches(cond: &RuleCondition, ctx: &RunContext, action: &ActionDescriptor) -> bool {
    match cond {
        RuleCondition::Always => true,
        RuleCondition::ActionTypeMatch(types) => types.contains(&action.action_type),
        RuleCondition::ResourcePattern(pat) => {
            resource_matches(pat, resource_field(&action.resource))
        }
        RuleCondition::CostAbove(threshold) => action
            .cost_estimate_usd
            .map(|c| c > *threshold)
            .unwrap_or(false),
        RuleCondition::BudgetRemainingBelow(threshold) => {
            budget_remaining(&ctx.budget) < *threshold
        }
        RuleCondition::And(parts) => parts.iter().all(|c| condition_matches(c, ctx, action)),
        RuleCondition::Or(parts) => parts.iter().any(|c| condition_matches(c, ctx, action)),
        RuleCondition::Not(inner) => !condition_matches(inner, ctx, action),
    }
}

/// Shareable handle for concurrent policy evaluation and reload.
#[derive(Debug, Clone)]
pub struct PolicyEvaluatorHandle {
    inner: Arc<RwLock<PolicyEvaluator>>,
}

impl PolicyEvaluatorHandle {
    pub fn new(evaluator: PolicyEvaluator) -> Self {
        Self {
            inner: Arc::new(RwLock::new(evaluator)),
        }
    }

    pub fn evaluate(&self, context: &RunContext, action: &ActionDescriptor) -> PolicyDecision {
        self.inner.read().evaluate(context, action)
    }

    pub fn reload(&self, new_set: CompiledPolicySet) {
        self.inner.write().hot_reload(new_set);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use rust_decimal::Decimal;
    use serde_json::json;
    use std::collections::HashMap;
    use std::time::Duration;
    use uuid::Uuid;

    fn test_context(tenant: Uuid, budget: BudgetSnapshot) -> RunContext {
        RunContext {
            tenant_id: tenant,
            run_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            workspace_id: None,
            project_id: None,
            policy_version_id: None,
            mode: crate::types::RunMode::Enforce,
            goal_text: "test goal".into(),
            started_at: Utc::now(),
            step_index: 0,
            budget,
            labels: HashMap::new(),
            metadata: json!({}),
        }
    }

    fn test_budget(actual: Decimal, limit: Decimal) -> BudgetSnapshot {
        BudgetSnapshot {
            reserved_usd: Decimal::ZERO,
            estimated_usd: Decimal::ZERO,
            actual_usd: actual,
            limit_usd: limit,
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn rules_evaluated_in_priority_order() {
        let tid = Uuid::new_v4();
        let ctx = test_context(
            tid,
            test_budget(
                Decimal::from_str_exact("1").unwrap(),
                Decimal::from_str_exact("100").unwrap(),
            ),
        );
        let action = ActionDescriptor {
            action_type: ActionType::Write,
            resource: "/tmp/a".into(),
            cost_estimate_usd: None,
            metadata: HashMap::new(),
        };

        let rules = vec![
            PolicyRule {
                id: "low".into(),
                name: "second".into(),
                priority: 10,
                condition: RuleCondition::Always,
                action: PolicyDecision::Deny {
                    reason_code: ReasonCode::new("LOW_PRIO"),
                    detail: None,
                },
                enabled: true,
            },
            PolicyRule {
                id: "high".into(),
                name: "first".into(),
                priority: 1,
                condition: RuleCondition::Always,
                action: PolicyDecision::Allow {
                    reason_code: ReasonCode::new("HIGH_PRIO"),
                },
                enabled: true,
            },
        ];

        let set = CompiledPolicySet::new(
            rules,
            PolicyDecision::Deny {
                reason_code: ReasonCode::new("DEFAULT"),
                detail: None,
            },
            Uuid::new_v4(),
            tid,
        );

        let ev = PolicyEvaluator::new();
        let mut ev = ev;
        ev.load_policy_set(set);
        let d = ev.evaluate(&ctx, &action);
        match d {
            PolicyDecision::Allow { reason_code } => assert_eq!(reason_code.as_str(), "HIGH_PRIO"),
            _ => panic!("expected Allow from higher-priority rule"),
        }
    }

    #[test]
    fn disabled_rules_skipped() {
        let tid = Uuid::new_v4();
        let ctx = test_context(tid, test_budget(Decimal::ZERO, Decimal::from(10)));
        let action = ActionDescriptor::simple(ActionType::ToolCall, "t");

        let rules = vec![PolicyRule {
            id: "off".into(),
            name: "n".into(),
            priority: 1,
            condition: RuleCondition::Always,
            action: PolicyDecision::Deny {
                reason_code: ReasonCode::new("X"),
                detail: None,
            },
            enabled: false,
        }];

        let set = CompiledPolicySet::new(
            rules,
            PolicyDecision::Allow {
                reason_code: ReasonCode::new("DEFAULT_OK"),
            },
            Uuid::new_v4(),
            tid,
        );

        let mut ev = PolicyEvaluator::new();
        ev.load_policy_set(set);
        let d = ev.evaluate(&ctx, &action);
        assert!(matches!(d, PolicyDecision::Allow { .. }));
    }

    #[test]
    fn tenant_mismatch_denies() {
        let tid = Uuid::new_v4();
        let ctx = test_context(tid, test_budget(Decimal::ZERO, Decimal::from(10)));
        let action = ActionDescriptor::simple(ActionType::ToolCall, "r");

        let set = CompiledPolicySet::new(
            vec![],
            PolicyDecision::Allow {
                reason_code: ReasonCode::new("OK"),
            },
            Uuid::new_v4(),
            Uuid::new_v4(),
        );

        let mut ev = PolicyEvaluator::new();
        ev.load_policy_set(set);
        let d = ev.evaluate(&ctx, &action);
        assert!(matches!(d, PolicyDecision::Deny { .. }));
    }

    #[test]
    fn resource_pattern_prefix_and_glob() {
        let tid = Uuid::new_v4();
        let ctx = test_context(tid, test_budget(Decimal::ZERO, Decimal::from(10)));

        let mut ev = PolicyEvaluator::new();
        ev.load_policy_set(CompiledPolicySet::new(
            vec![PolicyRule {
                id: "p".into(),
                name: "n".into(),
                priority: 1,
                condition: RuleCondition::ResourcePattern("/etc/*".into()),
                action: PolicyDecision::Deny {
                    reason_code: ReasonCode::new("PATH"),
                    detail: None,
                },
                enabled: true,
            }],
            PolicyDecision::Allow {
                reason_code: ReasonCode::new("OK"),
            },
            Uuid::new_v4(),
            tid,
        ));

        let denied = ev.evaluate(
            &ctx,
            &ActionDescriptor {
                action_type: ActionType::Write,
                resource: "/etc/passwd".into(),
                cost_estimate_usd: None,
                metadata: HashMap::new(),
            },
        );
        assert!(matches!(denied, PolicyDecision::Deny { .. }));

        let allowed = ev.evaluate(
            &ctx,
            &ActionDescriptor {
                action_type: ActionType::Write,
                resource: "/tmp/x".into(),
                cost_estimate_usd: None,
                metadata: HashMap::new(),
            },
        );
        assert!(matches!(allowed, PolicyDecision::Allow { .. }));
    }

    #[test]
    fn cost_and_budget_conditions() {
        let tid = Uuid::new_v4();
        let ctx = test_context(
            tid,
            test_budget(
                Decimal::from_str_exact("95").unwrap(),
                Decimal::from_str_exact("100").unwrap(),
            ),
        );
        let mut ev = PolicyEvaluator::new();
        ev.load_policy_set(CompiledPolicySet::new(
            vec![
                PolicyRule {
                    id: "c".into(),
                    name: "cost".into(),
                    priority: 1,
                    condition: RuleCondition::CostAbove(Decimal::from_str_exact("10").unwrap()),
                    action: PolicyDecision::Deny {
                        reason_code: ReasonCode::new("COST"),
                        detail: None,
                    },
                    enabled: true,
                },
                PolicyRule {
                    id: "b".into(),
                    name: "budget".into(),
                    priority: 2,
                    condition: RuleCondition::BudgetRemainingBelow(
                        Decimal::from_str_exact("20").unwrap(),
                    ),
                    action: PolicyDecision::RequireApproval {
                        reason_code: ReasonCode::new("BUDGET_LOW"),
                        witness_required: false,
                    },
                    enabled: true,
                },
            ],
            PolicyDecision::Allow {
                reason_code: ReasonCode::new("OK"),
            },
            Uuid::new_v4(),
            tid,
        ));

        let action_costly = ActionDescriptor {
            action_type: ActionType::ModelCall,
            resource: String::new(),
            cost_estimate_usd: Some(Decimal::from_str_exact("50").unwrap()),
            metadata: HashMap::new(),
        };
        assert!(matches!(
            ev.evaluate(&ctx, &action_costly),
            PolicyDecision::Deny { .. }
        ));

        let action_cheap = ActionDescriptor {
            action_type: ActionType::ModelCall,
            resource: String::new(),
            cost_estimate_usd: Some(Decimal::from_str_exact("1").unwrap()),
            metadata: HashMap::new(),
        };
        assert!(matches!(
            ev.evaluate(&ctx, &action_cheap),
            PolicyDecision::RequireApproval { .. }
        ));
    }

    #[test]
    fn boolean_combinators() {
        let tid = Uuid::new_v4();
        let ctx = test_context(tid, test_budget(Decimal::ZERO, Decimal::from(100)));
        let _action = ActionDescriptor::simple(ActionType::ToolCall, "curl");

        let cond = RuleCondition::And(vec![
            RuleCondition::ActionTypeMatch(vec![ActionType::ToolCall]),
            RuleCondition::Not(Box::new(RuleCondition::ResourcePattern("/safe/*".into()))),
        ]);

        let mut ev = PolicyEvaluator::new();
        ev.load_policy_set(CompiledPolicySet::new(
            vec![PolicyRule {
                id: "x".into(),
                name: "n".into(),
                priority: 1,
                condition: cond,
                action: PolicyDecision::Deny {
                    reason_code: ReasonCode::new("COMBO"),
                    detail: None,
                },
                enabled: true,
            }],
            PolicyDecision::Allow {
                reason_code: ReasonCode::new("OK"),
            },
            Uuid::new_v4(),
            tid,
        ));

        let hit = ev.evaluate(
            &ctx,
            &ActionDescriptor {
                action_type: ActionType::ToolCall,
                resource: "/unsafe/x".into(),
                cost_estimate_usd: None,
                metadata: HashMap::new(),
            },
        );
        assert!(matches!(hit, PolicyDecision::Deny { .. }));

        let miss = ev.evaluate(
            &ctx,
            &ActionDescriptor {
                action_type: ActionType::ToolCall,
                resource: "/safe/x".into(),
                cost_estimate_usd: None,
                metadata: HashMap::new(),
            },
        );
        assert!(matches!(miss, PolicyDecision::Allow { .. }));
    }

    #[test]
    fn handle_reload_is_visible() {
        let tid = Uuid::new_v4();
        let ctx = test_context(tid, test_budget(Decimal::ZERO, Decimal::from(10)));
        let action = ActionDescriptor::simple(ActionType::Custom("other".into()), "x");

        let v1 = Uuid::new_v4();
        let mut inner = PolicyEvaluator::new();
        inner.load_policy_set(CompiledPolicySet::new(
            vec![],
            PolicyDecision::Allow {
                reason_code: ReasonCode::new("V1"),
            },
            v1,
            tid,
        ));
        let h = PolicyEvaluatorHandle::new(inner);
        assert_eq!(
            h.evaluate(&ctx, &action),
            PolicyDecision::Allow {
                reason_code: ReasonCode::new("V1"),
            }
        );

        let v2 = Uuid::new_v4();
        h.reload(CompiledPolicySet::new(
            vec![],
            PolicyDecision::Deny {
                reason_code: ReasonCode::new("V2"),
                detail: None,
            },
            v2,
            tid,
        ));
        assert!(matches!(
            h.evaluate(&ctx, &action),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn evaluator_hot_path_budget_micros() {
        let tid = Uuid::new_v4();
        let ctx = test_context(
            tid,
            test_budget(
                Decimal::from_str_exact("1").unwrap(),
                Decimal::from_str_exact("1000000").unwrap(),
            ),
        );
        let action = ActionDescriptor {
            action_type: ActionType::ToolCall,
            resource: "/data/records/001".into(),
            cost_estimate_usd: Some(Decimal::from_str_exact("0.001").unwrap()),
            metadata: HashMap::new(),
        };

        let mut rules = Vec::new();
        for i in 0..128 {
            rules.push(PolicyRule {
                id: format!("r{i}"),
                name: format!("rule{i}"),
                priority: i,
                condition: RuleCondition::Or(vec![
                    RuleCondition::ActionTypeMatch(vec![ActionType::ModelCall, ActionType::Write]),
                    RuleCondition::And(vec![
                        RuleCondition::ResourcePattern("/data/*".into()),
                        RuleCondition::Not(Box::new(RuleCondition::CostAbove(
                            Decimal::from_str_exact("999999").unwrap(),
                        ))),
                    ]),
                ]),
                action: PolicyDecision::Allow {
                    reason_code: ReasonCode::new("RULE_HIT"),
                },
                enabled: true,
            });
        }

        let mut ev = PolicyEvaluator::new();
        ev.load_policy_set(CompiledPolicySet::new(
            rules,
            PolicyDecision::Allow {
                reason_code: ReasonCode::new("DEFAULT"),
            },
            Uuid::new_v4(),
            tid,
        ));

        let start = std::time::Instant::now();
        for _ in 0..2000 {
            std::hint::black_box(ev.evaluate(&ctx, &action));
        }
        let elapsed = start.elapsed();
        let per = elapsed / 2000;
        // Hot-path target is <100µs p99; allow slack for shared CI hosts.
        assert!(
            per < Duration::from_micros(500),
            "perf regression: {per:?} per iteration (design target < 100µs p99)"
        );
    }
}
