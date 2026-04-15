//! High-level facade: capture at approval, verify before execution.

use agentfirewall_core::types::{PolicyDecision, ReasonCode, StateCapture, WitnessResult};
use serde_json::{json, Value};

use crate::capture::{StateSnapshot, WitnessCapture, WitnessError};
use crate::revalidation::{RevalidationOutcome, Revalidator};

/// Facade combining witness capture and revalidation.
#[derive(Debug, Default, Clone)]
pub struct WitnessGuard;

impl WitnessGuard {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Capture state for attachment to an approval record.
    pub fn capture_for_approval<S: StateCapture>(
        &self,
        source: &S,
        resource_uri: &str,
    ) -> Result<StateSnapshot, WitnessError> {
        WitnessCapture::capture(source, resource_uri)
    }

    /// Capture canonical JSON for attachment to an approval record.
    pub fn capture_json_for_approval(
        &self,
        value: &Value,
        resource_uri: &str,
    ) -> Result<StateSnapshot, WitnessError> {
        WitnessCapture::capture_json(value, resource_uri)
    }

    /// Verify opaque preimage still matches before execution.
    pub fn verify_before_execution<S: StateCapture>(
        &self,
        original: &StateSnapshot,
        source: &S,
    ) -> Result<RevalidationOutcome, WitnessError> {
        Revalidator::revalidate(original, source)
    }

    /// Verify JSON still matches (canonical comparison) before execution.
    pub fn verify_json_before_execution(
        &self,
        original: &StateSnapshot,
        current: &Value,
    ) -> Result<RevalidationOutcome, WitnessError> {
        Revalidator::revalidate_json(original, current)
    }

    /// Maps a revalidation outcome to an optional policy [`ReasonCode`].
    ///
    /// Returns [`None`] when the witness is still valid; [`Some`] when state changed.
    #[must_use]
    pub fn to_reason_code(outcome: &RevalidationOutcome) -> Option<ReasonCode> {
        match &outcome.result {
            WitnessResult::Valid => None,
            WitnessResult::StateChanged { .. } => Some(ReasonCode::new("WITNESS_MISMATCH")),
        }
    }

    /// Maps outcome to an allow/deny [`PolicyDecision`].
    #[must_use]
    pub fn to_policy_decision(outcome: &RevalidationOutcome) -> PolicyDecision {
        match &outcome.result {
            WitnessResult::Valid => PolicyDecision::Allow {
                reason_code: ReasonCode::new("WITNESS_OK"),
            },
            WitnessResult::StateChanged { changed_fields, .. } => PolicyDecision::Deny {
                reason_code: ReasonCode::new("WITNESS_MISMATCH"),
                detail: Some(json!({ "changed_fields": changed_fields })),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::sync::Arc;

    struct MutableState {
        cell: Arc<AtomicU8>,
    }

    impl StateCapture for MutableState {
        type Error = Infallible;

        fn capture_witness_preimage(&self) -> Result<Vec<u8>, Self::Error> {
            Ok(vec![self.cell.load(Ordering::SeqCst)])
        }
    }

    #[test]
    fn end_to_end_approval_then_execution_ok() {
        let g = WitnessGuard::new();
        let st = MutableState {
            cell: Arc::new(AtomicU8::new(42)),
        };
        let snap = g.capture_for_approval(&st, "urn:live").unwrap();
        let out = g.verify_before_execution(&snap, &st).unwrap();
        assert_eq!(out.result, WitnessResult::Valid);
        assert!(WitnessGuard::to_reason_code(&out).is_none());
        match WitnessGuard::to_policy_decision(&out) {
            PolicyDecision::Allow { reason_code } => {
                assert_eq!(reason_code.as_str(), "WITNESS_OK");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn end_to_end_state_change_deny() {
        let g = WitnessGuard::new();
        let st = MutableState {
            cell: Arc::new(AtomicU8::new(1)),
        };
        let snap = g.capture_for_approval(&st, "urn:live").unwrap();
        st.cell.store(2, Ordering::SeqCst);
        let out = g.verify_before_execution(&snap, &st).unwrap();
        let code = WitnessGuard::to_reason_code(&out).unwrap();
        assert_eq!(code.as_str(), "WITNESS_MISMATCH");
        match WitnessGuard::to_policy_decision(&out) {
            PolicyDecision::Deny {
                reason_code,
                detail,
            } => {
                assert_eq!(reason_code.as_str(), "WITNESS_MISMATCH");
                let d = detail.unwrap();
                assert!(d.get("changed_fields").is_some());
            }
            _ => panic!(),
        }
    }

    #[test]
    fn json_flow_field_detail_in_policy() {
        let g = WitnessGuard::new();
        let v0 = json!({"id": 1, "status": "open"});
        let snap = g.capture_json_for_approval(&v0, "urn:issue").unwrap();
        let v1 = json!({"id": 1, "status": "closed"});
        let out = g.verify_json_before_execution(&snap, &v1).unwrap();
        let PolicyDecision::Deny { detail, .. } = WitnessGuard::to_policy_decision(&out) else {
            panic!();
        };
        let detail = detail.unwrap();
        let fields = detail.get("changed_fields").unwrap().as_array().unwrap();
        let status = Value::String("status".into());
        assert!(fields.contains(&status));
    }
}
