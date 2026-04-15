//! Compare live state against an approval-time [`StateSnapshot`](crate::capture::StateSnapshot).

use std::collections::BTreeSet;

use agentfirewall_core::types::{StateCapture, WitnessHash, WitnessResult};
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::canonical;
use crate::capture::{StateSnapshot, WitnessError, CURRENT_FORMAT_VERSION, MAX_SNAPSHOT_SIZE};
use crate::hash::{compute_witness_hash, constant_time_compare};

/// Outcome of revalidating witness state at execution time.
#[derive(Debug, Clone, PartialEq)]
pub struct RevalidationOutcome {
    pub result: WitnessResult,
    pub original_hash: WitnessHash,
    pub current_hash: WitnessHash,
    pub revalidated_at: DateTime<Utc>,
    pub elapsed_since_capture_ms: i64,
}

fn validate_original_for_revalidation(original: &StateSnapshot) -> Result<(), WitnessError> {
    if original.format_version != CURRENT_FORMAT_VERSION {
        return Err(WitnessError::CaptureFailure(format!(
            "unsupported witness snapshot format_version: {} (expected {})",
            original.format_version, CURRENT_FORMAT_VERSION
        )));
    }
    if original.size_bytes != original.preimage.len() {
        return Err(WitnessError::CaptureFailure(
            "snapshot size_bytes does not match preimage length".into(),
        ));
    }
    ensure_snapshot_size(original.preimage.len())?;
    let computed = compute_witness_hash(&original.preimage);
    if !constant_time_compare(&computed, &original.hash) {
        return Err(WitnessError::RevalidationFailed {
            expected: original.hash,
            actual: computed,
            changed_fields: vec!["snapshot.hash".into()],
        });
    }
    Ok(())
}

fn ensure_snapshot_size(len: usize) -> Result<(), WitnessError> {
    if len > MAX_SNAPSHOT_SIZE {
        return Err(WitnessError::SnapshotTooLarge {
            size: len,
            max: MAX_SNAPSHOT_SIZE,
        });
    }
    Ok(())
}

fn finish_outcome(
    original: &StateSnapshot,
    current_hash: WitnessHash,
    matches: bool,
    changed_fields: Option<Vec<String>>,
    revalidated_at: DateTime<Utc>,
) -> RevalidationOutcome {
    let result = if matches {
        WitnessResult::Valid
    } else {
        WitnessResult::StateChanged {
            expected: original.hash,
            current: current_hash,
            changed_fields,
        }
    };
    let elapsed_since_capture_ms = revalidated_at
        .signed_duration_since(original.captured_at)
        .num_milliseconds();
    RevalidationOutcome {
        result,
        original_hash: original.hash,
        current_hash,
        revalidated_at,
        elapsed_since_capture_ms,
    }
}

/// Best-effort JSON path diff for mismatched canonical documents.
pub(crate) fn json_changed_fields(original: &Value, current: &Value) -> Vec<String> {
    json_diff_paths_value(original, current, "")
}

fn json_diff_paths_value(orig: &Value, cur: &Value, prefix: &str) -> Vec<String> {
    if orig == cur {
        return vec![];
    }
    match (orig, cur) {
        (Value::Object(o1), Value::Object(o2)) => {
            let keys: BTreeSet<_> = o1.keys().chain(o2.keys()).cloned().collect();
            let mut out = Vec::new();
            for k in keys {
                let path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                match (o1.get(&k), o2.get(&k)) {
                    (None, Some(_)) | (Some(_), None) => out.push(path),
                    (Some(v1), Some(v2)) => out.extend(json_diff_paths_value(v1, v2, &path)),
                    (None, None) => {}
                }
            }
            out.sort();
            out.dedup();
            out
        }
        (Value::Array(a1), Value::Array(a2)) => {
            if a1 == a2 {
                return vec![];
            }
            if a1.len() != a2.len() {
                return vec![if prefix.is_empty() {
                    "[]".into()
                } else {
                    prefix.to_string()
                }];
            }
            let mut out = Vec::new();
            for (i, (e1, e2)) in a1.iter().zip(a2.iter()).enumerate() {
                let path = if prefix.is_empty() {
                    format!("[{i}]")
                } else {
                    format!("{prefix}[{i}]")
                };
                out.extend(json_diff_paths_value(e1, e2, &path));
            }
            out.sort();
            out.dedup();
            out
        }
        _ => vec![if prefix.is_empty() {
            "$".into()
        } else {
            prefix.to_string()
        }],
    }
}

/// Revalidates live state against a prior snapshot.
pub struct Revalidator;

impl Revalidator {
    /// Captures current preimage from `source` and compares to `original`.
    pub fn revalidate<S: StateCapture>(
        original: &StateSnapshot,
        source: &S,
    ) -> Result<RevalidationOutcome, WitnessError> {
        validate_original_for_revalidation(original)?;
        let revalidated_at = Utc::now();
        let current_preimage = source
            .capture_witness_preimage()
            .map_err(|e| WitnessError::CaptureFailure(e.to_string()))?;
        ensure_snapshot_size(current_preimage.len())?;
        let current_hash = compute_witness_hash(&current_preimage);
        let matches = constant_time_compare(&original.hash, &current_hash);
        let changed_fields = if matches {
            None
        } else {
            match (
                serde_json::from_slice::<Value>(&original.preimage),
                serde_json::from_slice::<Value>(&current_preimage),
            ) {
                (Ok(o), Ok(c)) => {
                    let paths = json_changed_fields(&o, &c);
                    Some(if paths.is_empty() {
                        vec!["$".into()]
                    } else {
                        paths
                    })
                }
                _ => None,
            }
        };
        Ok(finish_outcome(
            original,
            current_hash,
            matches,
            changed_fields,
            revalidated_at,
        ))
    }

    /// Canonicalizes `current_value` and compares to `original` (JSON path).
    pub fn revalidate_json(
        original: &StateSnapshot,
        current_value: &Value,
    ) -> Result<RevalidationOutcome, WitnessError> {
        validate_original_for_revalidation(original)?;
        let revalidated_at = Utc::now();
        let current_preimage = canonical::canonicalize(current_value)?;
        ensure_snapshot_size(current_preimage.len())?;
        let current_hash = compute_witness_hash(&current_preimage);
        let matches = constant_time_compare(&original.hash, &current_hash);
        let changed_fields = if matches {
            None
        } else {
            match serde_json::from_slice::<Value>(&original.preimage) {
                Ok(o) => {
                    let paths = json_changed_fields(&o, current_value);
                    Some(if paths.is_empty() {
                        vec!["$".into()]
                    } else {
                        paths
                    })
                }
                Err(_) => None,
            }
        };
        Ok(finish_outcome(
            original,
            current_hash,
            matches,
            changed_fields,
            revalidated_at,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::WitnessCapture;
    use chrono::Duration;
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

    fn snap_with_past_capture(json: Value, ago: Duration) -> StateSnapshot {
        let mut s = WitnessCapture::capture_json(&json, "urn:test").unwrap();
        s.captured_at = Utc::now() - ago;
        s
    }

    #[test]
    fn identical_json_passes() {
        let v = json!({"a": 1, "b": {"c": 2}});
        let original = WitnessCapture::capture_json(&v, "urn:x").unwrap();
        let out = Revalidator::revalidate_json(&original, &v).unwrap();
        assert_eq!(out.result, WitnessResult::Valid);
        assert!(constant_time_compare(&out.original_hash, &out.current_hash));
        assert_eq!(out.original_hash, out.current_hash);
    }

    #[test]
    fn identical_opaque_bytes_passes() {
        let st = MutableState {
            cell: Arc::new(AtomicU8::new(7)),
        };
        let original = WitnessCapture::capture(&st, "urn:bytes").unwrap();
        let out = Revalidator::revalidate(&original, &st).unwrap();
        assert_eq!(out.result, WitnessResult::Valid);
    }

    #[test]
    fn modified_json_reports_state_changed_and_fields() {
        let v0 = json!({"name": "ada", "nested": {"x": 1}});
        let original = WitnessCapture::capture_json(&v0, "urn:doc").unwrap();
        let v1 = json!({"name": "bob", "nested": {"x": 1}});
        let out = Revalidator::revalidate_json(&original, &v1).unwrap();
        match &out.result {
            WitnessResult::StateChanged {
                expected,
                current,
                changed_fields,
            } => {
                assert_eq!(*expected, original.hash);
                assert_ne!(expected, current);
                let fields = changed_fields.as_ref().unwrap();
                assert!(fields.contains(&"name".to_string()));
            }
            _ => panic!("expected StateChanged"),
        }
    }

    #[test]
    fn nested_field_diff() {
        let v0 = json!({"nested": {"x": 1, "y": 2}});
        let v1 = json!({"nested": {"x": 9, "y": 2}});
        let original = WitnessCapture::capture_json(&v0, "u").unwrap();
        let out = Revalidator::revalidate_json(&original, &v1).unwrap();
        let WitnessResult::StateChanged { changed_fields, .. } = &out.result else {
            panic!();
        };
        assert!(changed_fields
            .as_ref()
            .unwrap()
            .contains(&"nested.x".to_string()));
    }

    #[test]
    fn array_length_mismatch_path() {
        let v0 = json!({"items": [1, 2, 3]});
        let v1 = json!({"items": [1, 2]});
        let original = WitnessCapture::capture_json(&v0, "u").unwrap();
        let out = Revalidator::revalidate_json(&original, &v1).unwrap();
        let WitnessResult::StateChanged { changed_fields, .. } = &out.result else {
            panic!();
        };
        assert_eq!(changed_fields.as_ref().unwrap(), &vec!["items".to_string()]);
    }

    #[test]
    fn key_order_irrelevant_for_match() {
        let a = json!({"z": 1, "a": {"m": 2, "n": 3}});
        let b = json!({"a": {"n": 3, "m": 2}, "z": 1});
        let original = WitnessCapture::capture_json(&a, "u").unwrap();
        let out = Revalidator::revalidate_json(&original, &b).unwrap();
        assert_eq!(out.result, WitnessResult::Valid);
    }

    #[test]
    fn opaque_bytes_change_no_field_list() {
        let st = MutableState {
            cell: Arc::new(AtomicU8::new(1)),
        };
        let original = WitnessCapture::capture(&st, "u").unwrap();
        st.cell.store(2, Ordering::SeqCst);
        let out = Revalidator::revalidate(&original, &st).unwrap();
        let WitnessResult::StateChanged { changed_fields, .. } = &out.result else {
            panic!();
        };
        assert!(changed_fields.is_none());
    }

    #[test]
    fn wrong_format_version_errors() {
        let mut s = WitnessCapture::capture_json(&json!({}), "u").unwrap();
        s.format_version = 99;
        let err = Revalidator::revalidate_json(&s, &json!({})).unwrap_err();
        match err {
            WitnessError::CaptureFailure(m) => assert!(m.contains("format_version")),
            e => panic!("{e:?}"),
        }
    }

    #[test]
    fn tampered_hash_errors() {
        let mut s = WitnessCapture::capture_json(&json!({"k": 1}), "u").unwrap();
        s.hash = WitnessHash([0xff; 32]);
        let err = Revalidator::revalidate_json(&s, &json!({"k": 1})).unwrap_err();
        assert!(matches!(err, WitnessError::RevalidationFailed { .. }));
    }

    #[test]
    fn size_bytes_mismatch_errors() {
        let mut s = WitnessCapture::capture_json(&json!({}), "u").unwrap();
        s.size_bytes = 999;
        let err = Revalidator::revalidate_json(&s, &json!({})).unwrap_err();
        match err {
            WitnessError::CaptureFailure(m) => assert!(m.contains("size_bytes")),
            e => panic!("{e:?}"),
        }
    }

    #[test]
    fn elapsed_time_reflects_capture_timestamp() {
        let original = snap_with_past_capture(json!({"a": 1}), Duration::seconds(120));
        let out = Revalidator::revalidate_json(&original, &json!({"a": 1})).unwrap();
        assert!(out.elapsed_since_capture_ms >= 119_000);
    }

    #[test]
    fn json_diff_detects_added_key() {
        let o = json!({"a": 1});
        let c = json!({"a": 1, "b": 2});
        let paths = json_changed_fields(&o, &c);
        assert!(paths.contains(&"b".into()));
    }

    #[test]
    fn json_diff_detects_removed_key() {
        let o = json!({"a": 1, "b": 2});
        let c = json!({"a": 1});
        let paths = json_changed_fields(&o, &c);
        assert!(paths.contains(&"b".into()));
    }

    struct Oversized;

    impl StateCapture for Oversized {
        type Error = Infallible;

        fn capture_witness_preimage(&self) -> Result<Vec<u8>, Self::Error> {
            Ok(vec![0u8; MAX_SNAPSHOT_SIZE + 1])
        }
    }

    #[test]
    fn revalidate_rejects_oversized_current_preimage() {
        let original = WitnessCapture::capture_json(&json!({}), "u").unwrap();
        let err = Revalidator::revalidate(&original, &Oversized).unwrap_err();
        match err {
            WitnessError::SnapshotTooLarge { size, .. } => {
                assert_eq!(size, MAX_SNAPSHOT_SIZE + 1);
            }
            e => panic!("{e:?}"),
        }
    }
}
