//! Top-level error type for the Agent FirewallKit control plane.

use std::path::PathBuf;

use rust_decimal::Decimal;
use thiserror::Error;
use uuid::Uuid;

use crate::types::WitnessHash;

/// Errors surfaced by policy, witness, budget, transport, and serialization layers.
#[derive(Error, Debug)]
pub enum AgentFirewallError {
    #[error("policy evaluation failed: {0}")]
    PolicyEvaluation(String),

    #[error("witness mismatch: expected {expected:?}, actual {actual:?}")]
    WitnessMismatch {
        expected: WitnessHash,
        actual: WitnessHash,
    },

    #[error("budget exceeded: limit {limit}, actual {actual}")]
    BudgetExceeded { limit: Decimal, actual: Decimal },

    #[error("budget overflow: delta {delta}, actual {actual}, limit {limit}")]
    BudgetOverflow {
        delta: Decimal,
        actual: Decimal,
        limit: Decimal,
    },

    #[error("invalid configuration: {0}")]
    ConfigInvalid(String),

    #[error("invalid environment variable {var}: expected boolean, got {value}")]
    InvalidEnvBool { var: &'static str, value: String },

    #[error("invalid environment variable {var}: expected UUID, got {value}")]
    InvalidEnvUuid { var: &'static str, value: String },

    #[error("invalid environment variable {var}: expected number, got {value}")]
    InvalidEnvNumber { var: &'static str, value: String },

    #[error("I/O error reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("embedding failure: {0}")]
    EmbeddingFailure(String),

    #[error("transport unavailable: {0}")]
    TransportUnavailable(String),

    #[error("tenant isolation violation: {0}")]
    TenantIsolation(String),

    #[error("approval expired: {approval_id}")]
    ApprovalExpired { approval_id: Uuid },

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl AgentFirewallError {
    #[must_use]
    pub fn config(msg: impl Into<String>) -> Self {
        Self::ConfigInvalid(msg.into())
    }
}

impl From<serde_json::Error> for AgentFirewallError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value.to_string())
    }
}

impl From<std::io::Error> for AgentFirewallError {
    fn from(value: std::io::Error) -> Self {
        Self::Internal(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn display_policy_evaluation() {
        let e = AgentFirewallError::PolicyEvaluation("rule x".into());
        assert!(e.to_string().contains("rule x"));
    }

    #[test]
    fn witness_mismatch_display_contains_debug_hashes() {
        let e = AgentFirewallError::WitnessMismatch {
            expected: WitnessHash([0; 32]),
            actual: WitnessHash([0xff; 32]),
        };
        let s = e.to_string();
        assert!(s.contains("WitnessHash"));
    }

    #[test]
    fn budget_exceeded_display() {
        let e = AgentFirewallError::BudgetExceeded {
            limit: Decimal::ONE,
            actual: Decimal::new(2, 0),
        };
        assert!(e.to_string().contains('1'));
    }

    #[test]
    fn from_serde_json_error() {
        let err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let av: AgentFirewallError = err.into();
        match av {
            AgentFirewallError::Serialization(msg) => assert!(!msg.is_empty()),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "missing");
        let av: AgentFirewallError = io_err.into();
        match av {
            AgentFirewallError::Internal(msg) => assert!(msg.contains("missing")),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn approval_expired_roundtrip_message() {
        let id = Uuid::nil();
        let e = AgentFirewallError::ApprovalExpired { approval_id: id };
        assert!(e.to_string().contains(&id.to_string()));
    }
}
