//! Registry of predefined [`ReasonCode`](crate::types::ReasonCode) metadata.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::AgentFirewallError;
use crate::types::ReasonCode;

/// Coarse grouping for reason codes (progress, witness, budget, policy, system).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonFamily {
    Progress,
    Witness,
    Budget,
    Policy,
    System,
}

/// Severity hint for operators and dashboards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Human-oriented metadata for a single reason code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReasonEntry {
    pub code: ReasonCode,
    pub family: ReasonFamily,
    pub human_message: String,
    pub severity: Severity,
}

/// In-memory catalog of known reason codes and their descriptions.
#[derive(Debug, Clone, Default)]
pub struct ReasonCodeRegistry {
    entries: HashMap<ReasonCode, ReasonEntry>,
}

impl ReasonCodeRegistry {
    /// Default message and severity when a code is not registered.
    pub const UNKNOWN_MESSAGE: &'static str = "Unknown reason code";
    pub const UNKNOWN_SEVERITY: Severity = Severity::Warning;

    #[must_use]
    pub fn new() -> Self {
        let mut reg = Self {
            entries: HashMap::new(),
        };
        for entry in Self::predefined_entries() {
            reg.entries.insert(entry.code.clone(), entry);
        }
        reg
    }

    fn predefined_entries() -> Vec<ReasonEntry> {
        vec![
            ReasonEntry {
                code: ReasonCode::new("PROGRESS_STALL"),
                family: ReasonFamily::Progress,
                human_message: "Agent has made no meaningful progress for N consecutive steps"
                    .into(),
                severity: Severity::Warning,
            },
            ReasonEntry {
                code: ReasonCode::new("PROGRESS_REGRESSION"),
                family: ReasonFamily::Progress,
                human_message: "Agent's progress has regressed from previous step".into(),
                severity: Severity::Warning,
            },
            ReasonEntry {
                code: ReasonCode::new("PROGRESS_GOAL_DRIFT"),
                family: ReasonFamily::Progress,
                human_message: "Agent's actions are diverging from the declared goal".into(),
                severity: Severity::Warning,
            },
            ReasonEntry {
                code: ReasonCode::new("WITNESS_MISMATCH"),
                family: ReasonFamily::Witness,
                human_message: "State has changed since approval was granted".into(),
                severity: Severity::Error,
            },
            ReasonEntry {
                code: ReasonCode::new("WITNESS_EXPIRED"),
                family: ReasonFamily::Witness,
                human_message: "Approval has expired before execution".into(),
                severity: Severity::Error,
            },
            ReasonEntry {
                code: ReasonCode::new("BUDGET_SOFT_LIMIT"),
                family: ReasonFamily::Budget,
                human_message: "Approaching budget limit".into(),
                severity: Severity::Warning,
            },
            ReasonEntry {
                code: ReasonCode::new("BUDGET_HARD_LIMIT"),
                family: ReasonFamily::Budget,
                human_message: "Budget limit exceeded; action blocked".into(),
                severity: Severity::Critical,
            },
            ReasonEntry {
                code: ReasonCode::new("BUDGET_UNKNOWN_COST"),
                family: ReasonFamily::Budget,
                human_message: "Cost cannot be estimated for this action".into(),
                severity: Severity::Warning,
            },
            ReasonEntry {
                code: ReasonCode::new("POLICY_DENY"),
                family: ReasonFamily::Policy,
                human_message: "Action denied by policy rule".into(),
                severity: Severity::Error,
            },
            ReasonEntry {
                code: ReasonCode::new("POLICY_REQUIRE_APPROVAL"),
                family: ReasonFamily::Policy,
                human_message: "Action requires human approval".into(),
                severity: Severity::Info,
            },
            ReasonEntry {
                code: ReasonCode::new("POLICY_DOWNGRADE"),
                family: ReasonFamily::Policy,
                human_message: "Action permitted with reduced capabilities".into(),
                severity: Severity::Warning,
            },
            ReasonEntry {
                code: ReasonCode::new("SYSTEM_EMBED_FAILURE"),
                family: ReasonFamily::System,
                human_message: "Embedding model unavailable; falling back".into(),
                severity: Severity::Warning,
            },
            ReasonEntry {
                code: ReasonCode::new("SYSTEM_TRANSPORT_DOWN"),
                family: ReasonFamily::System,
                human_message: "Control plane connection unavailable".into(),
                severity: Severity::Critical,
            },
        ]
    }

    #[must_use]
    pub fn lookup(&self, code: &ReasonCode) -> Option<&ReasonEntry> {
        self.entries.get(code)
    }

    /// Insert a new reason entry, or accept a no-op if the same entry is registered again.
    /// Returns [`AgentFirewallError::ConfigInvalid`] if the code exists with different metadata.
    pub fn register(&mut self, entry: ReasonEntry) -> Result<(), AgentFirewallError> {
        match self.entries.get(&entry.code) {
            Some(existing) if existing == &entry => Ok(()),
            Some(existing) => Err(AgentFirewallError::ConfigInvalid(format!(
                "reason code {} is already registered with different metadata (existing family {:?}, new {:?})",
                entry.code.as_str(),
                existing.family,
                entry.family
            ))),
            None => {
                self.entries.insert(entry.code.clone(), entry);
                Ok(())
            }
        }
    }

    #[must_use]
    pub fn human_message(&self, code: &ReasonCode) -> &str {
        self.lookup(code)
            .map(|e| e.human_message.as_str())
            .unwrap_or(Self::UNKNOWN_MESSAGE)
    }

    #[must_use]
    pub fn severity(&self, code: &ReasonCode) -> Severity {
        self.lookup(code)
            .map(|e| e.severity)
            .unwrap_or(Self::UNKNOWN_SEVERITY)
    }

    /// All entries belonging to a family (order not specified).
    #[must_use]
    pub fn entries_in_family(&self, family: ReasonFamily) -> Vec<&ReasonEntry> {
        self.entries
            .values()
            .filter(|e| e.family == family)
            .collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_has_all_predefined() {
        let reg = ReasonCodeRegistry::new();
        assert_eq!(reg.len(), 13);
        let codes = [
            "PROGRESS_STALL",
            "PROGRESS_REGRESSION",
            "PROGRESS_GOAL_DRIFT",
            "WITNESS_MISMATCH",
            "WITNESS_EXPIRED",
            "BUDGET_SOFT_LIMIT",
            "BUDGET_HARD_LIMIT",
            "BUDGET_UNKNOWN_COST",
            "POLICY_DENY",
            "POLICY_REQUIRE_APPROVAL",
            "POLICY_DOWNGRADE",
            "SYSTEM_EMBED_FAILURE",
            "SYSTEM_TRANSPORT_DOWN",
        ];
        for c in codes {
            let rc = ReasonCode::new(c);
            assert!(reg.lookup(&rc).is_some(), "missing {c}");
        }
    }

    #[test]
    fn lookup_returns_message_and_severity() {
        let reg = ReasonCodeRegistry::new();
        let code = ReasonCode::new("POLICY_DENY");
        let entry = reg.lookup(&code).unwrap();
        assert_eq!(entry.family, ReasonFamily::Policy);
        assert_eq!(entry.severity, Severity::Error);
        assert!(entry.human_message.contains("denied"));
    }

    #[test]
    fn unknown_code_human_message_and_severity() {
        let reg = ReasonCodeRegistry::new();
        let code = ReasonCode::new("TOTALLY_UNKNOWN");
        assert_eq!(reg.lookup(&code), None);
        assert_eq!(
            reg.human_message(&code),
            ReasonCodeRegistry::UNKNOWN_MESSAGE
        );
        assert_eq!(reg.severity(&code), ReasonCodeRegistry::UNKNOWN_SEVERITY);
    }

    #[test]
    fn register_new_code_ok() {
        let mut reg = ReasonCodeRegistry::new();
        let n = reg.len();
        let entry = ReasonEntry {
            code: ReasonCode::new("CUSTOM_TEST_CODE"),
            family: ReasonFamily::System,
            human_message: "custom".into(),
            severity: Severity::Info,
        };
        reg.register(entry.clone()).unwrap();
        assert_eq!(reg.len(), n + 1);
        assert_eq!(
            reg.lookup(&ReasonCode::new("CUSTOM_TEST_CODE")),
            Some(&entry)
        );
        reg.register(entry.clone()).unwrap();
        assert_eq!(reg.len(), n + 1);
    }

    #[test]
    fn register_duplicate_identical_ok() {
        let mut reg = ReasonCodeRegistry::new();
        let code = ReasonCode::new("POLICY_DENY");
        let entry = reg.lookup(&code).unwrap().clone();
        reg.register(entry).unwrap();
    }

    #[test]
    fn register_duplicate_different_metadata_err() {
        let mut reg = ReasonCodeRegistry::new();
        let err = reg
            .register(ReasonEntry {
                code: ReasonCode::new("POLICY_DENY"),
                family: ReasonFamily::System,
                human_message: "different".into(),
                severity: Severity::Critical,
            })
            .unwrap_err();
        match err {
            AgentFirewallError::ConfigInvalid(msg) => {
                assert!(msg.contains("POLICY_DENY"));
            }
            e => panic!("unexpected {e:?}"),
        }
    }

    #[test]
    fn family_filter_budget() {
        let reg = ReasonCodeRegistry::new();
        let budget = reg.entries_in_family(ReasonFamily::Budget);
        assert_eq!(budget.len(), 3);
        for e in budget {
            assert_eq!(e.family, ReasonFamily::Budget);
        }
    }

    #[test]
    fn family_filter_progress() {
        let reg = ReasonCodeRegistry::new();
        let p = reg.entries_in_family(ReasonFamily::Progress);
        assert_eq!(p.len(), 3);
    }
}
