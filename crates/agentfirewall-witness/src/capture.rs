//! Approval-time state capture: preimage, hash, and metadata.

use agentfirewall_core::types::{StateCapture, WitnessHash};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical::{self, CanonicalError};
use crate::hash::compute_witness_hash;

/// Maximum allowed witness preimage size (10 MiB).
pub const MAX_SNAPSHOT_SIZE: usize = 10 * 1024 * 1024;

/// Supported snapshot format; bump when wire layout or hashing rules change.
pub const CURRENT_FORMAT_VERSION: u8 = 1;

/// Approval-time witness: canonical preimage, digest, and capture metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub preimage: Vec<u8>,
    pub hash: WitnessHash,
    pub format_version: u8,
    pub captured_at: DateTime<Utc>,
    pub resource_uri: String,
    pub size_bytes: usize,
}

/// Errors from capture and snapshot construction.
#[derive(Debug, thiserror::Error)]
pub enum WitnessError {
    #[error("witness capture failed: {0}")]
    CaptureFailure(String),

    #[error(transparent)]
    CanonicalError(#[from] CanonicalError),

    #[error("witness snapshot too large: {size} bytes (max {max})")]
    SnapshotTooLarge { size: usize, max: usize },

    #[error(
        "witness revalidation failed: expected {expected:?}, actual {actual:?}; fields: {changed_fields:?}"
    )]
    RevalidationFailed {
        expected: WitnessHash,
        actual: WitnessHash,
        changed_fields: Vec<String>,
    },
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

fn build_snapshot(
    preimage: Vec<u8>,
    resource_uri: &str,
    format_version: u8,
) -> Result<StateSnapshot, WitnessError> {
    let size_bytes = preimage.len();
    ensure_snapshot_size(size_bytes)?;
    let hash = compute_witness_hash(&preimage);
    Ok(StateSnapshot {
        preimage,
        hash,
        format_version,
        captured_at: Utc::now(),
        resource_uri: resource_uri.to_owned(),
        size_bytes,
    })
}

/// Stateless capture helpers used by [`WitnessGuard`](crate::guard::WitnessGuard).
pub struct WitnessCapture;

impl WitnessCapture {
    /// Captures preimage from a [`StateCapture`] implementor and builds a snapshot.
    pub fn capture<S: StateCapture>(
        source: &S,
        resource_uri: &str,
    ) -> Result<StateSnapshot, WitnessError> {
        let preimage = source
            .capture_witness_preimage()
            .map_err(|e| WitnessError::CaptureFailure(e.to_string()))?;
        build_snapshot(preimage, resource_uri, CURRENT_FORMAT_VERSION)
    }

    /// Canonicalizes JSON, hashes it, and builds a snapshot.
    pub fn capture_json(value: &Value, resource_uri: &str) -> Result<StateSnapshot, WitnessError> {
        let preimage = canonical::canonicalize(value)?;
        build_snapshot(preimage, resource_uri, CURRENT_FORMAT_VERSION)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::CanonicalError;
    use serde_json::json;
    use std::convert::Infallible;

    struct Fixed(Vec<u8>);

    impl StateCapture for Fixed {
        type Error = Infallible;

        fn capture_witness_preimage(&self) -> Result<Vec<u8>, Self::Error> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn capture_round_trip_metadata() {
        let s = WitnessCapture::capture(&Fixed(vec![1, 2, 3]), "urn:test:state").unwrap();
        assert_eq!(s.format_version, CURRENT_FORMAT_VERSION);
        assert_eq!(s.resource_uri, "urn:test:state");
        assert_eq!(s.size_bytes, 3);
        assert_eq!(s.preimage, vec![1, 2, 3]);
        assert!(constant_time_matches_preimage(&s));
    }

    #[test]
    fn capture_json_matches_canonical_bytes() {
        let v = json!({"z": 1, "a": 2});
        let snap = WitnessCapture::capture_json(&v, "urn:json:doc").unwrap();
        let expected = canonical::canonicalize(&v).unwrap();
        assert_eq!(snap.preimage, expected);
        assert_eq!(snap.hash, compute_witness_hash(&expected));
    }

    #[test]
    fn snapshot_at_max_size_accepted() {
        let data = vec![0u8; MAX_SNAPSHOT_SIZE];
        let s = WitnessCapture::capture(&Fixed(data), "urn:max").unwrap();
        assert_eq!(s.size_bytes, MAX_SNAPSHOT_SIZE);
        assert_eq!(s.preimage.len(), MAX_SNAPSHOT_SIZE);
    }

    #[test]
    fn snapshot_too_large_rejected() {
        let big = vec![0u8; MAX_SNAPSHOT_SIZE + 1];
        let err = WitnessCapture::capture(&Fixed(big), "x").unwrap_err();
        match err {
            WitnessError::SnapshotTooLarge { size, max } => {
                assert_eq!(size, MAX_SNAPSHOT_SIZE + 1);
                assert_eq!(max, MAX_SNAPSHOT_SIZE);
            }
            e => panic!("unexpected {e:?}"),
        }
    }

    #[test]
    fn canonical_input_too_large_propagates() {
        let inner = "a".repeat(10 * 1024 * 1024);
        let v = json!({ "blob": inner });
        let err = WitnessCapture::capture_json(&v, "x").unwrap_err();
        match err {
            WitnessError::CanonicalError(CanonicalError::InputTooLarge { .. }) => {}
            e => panic!("unexpected {e:?}"),
        }
    }

    #[test]
    fn capture_failure_maps_source_error() {
        struct Fail;

        impl StateCapture for Fail {
            type Error = std::io::Error;

            fn capture_witness_preimage(&self) -> Result<Vec<u8>, Self::Error> {
                Err(std::io::Error::other("boom"))
            }
        }

        let err = WitnessCapture::capture(&Fail, "x").unwrap_err();
        match err {
            WitnessError::CaptureFailure(m) => assert!(m.contains("boom")),
            e => panic!("unexpected {e:?}"),
        }
    }

    fn constant_time_matches_preimage(s: &StateSnapshot) -> bool {
        crate::hash::constant_time_compare(&s.hash, &compute_witness_hash(&s.preimage))
    }
}
