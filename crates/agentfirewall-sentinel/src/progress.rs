//! Pure progress metrics between embedding similarity observations.

use agentfirewall_core::ProgressSnapshot;
use chrono::Utc;
use uuid::Uuid;

/// Stateless helpers for similarity deltas, EMA smoothing, and snapshot construction.
pub struct ProgressComputer;

/// Parameter bundle for [`ProgressComputer::build_snapshot`].
pub struct SnapshotParams<'a> {
    pub run_id: Uuid,
    pub step: u64,
    pub similarity: f32,
    pub delta: f32,
    pub ema_sim: f32,
    pub ema_delta: f32,
    pub stalls: u32,
    pub model: &'a str,
}

impl ProgressComputer {
    #[inline]
    pub fn compute_delta(current_similarity: f32, previous_similarity: f32) -> f32 {
        current_similarity - previous_similarity
    }

    /// Exponential moving average: `alpha * current + (1 - alpha) * previous_ema`.
    #[inline]
    pub fn compute_ema(current: f32, previous_ema: f32, alpha: f32) -> f32 {
        alpha * current + (1.0 - alpha) * previous_ema
    }

    /// True when the step-to-step change is too small to count as progress.
    #[inline]
    pub fn is_stall(delta: f32, threshold: f32) -> bool {
        if !delta.is_finite() || !threshold.is_finite() {
            return true;
        }
        delta.abs() < threshold
    }

    /// True when similarity dropped sharply vs the previous step.
    #[inline]
    pub fn is_regression(delta: f32, threshold: f32) -> bool {
        if !delta.is_finite() || !threshold.is_finite() {
            return false;
        }
        delta < threshold
    }

    /// Builds a [`ProgressSnapshot`] for the current observation.
    pub fn build_snapshot(p: SnapshotParams<'_>) -> ProgressSnapshot {
        ProgressSnapshot {
            run_id: p.run_id,
            step_index: p.step,
            similarity: p.similarity,
            delta: p.delta,
            ema_similarity: p.ema_sim,
            ema_delta: p.ema_delta,
            consecutive_stalls: p.stalls,
            embedding_model_revision: p.model.to_string(),
            observed_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delta_is_difference() {
        assert!((ProgressComputer::compute_delta(0.9, 0.8) - 0.1).abs() < 1e-6);
        assert!((ProgressComputer::compute_delta(0.5, 0.6) + 0.1).abs() < 1e-6);
    }

    #[test]
    fn ema_matches_formula() {
        let a = 0.3_f32;
        let cur = 1.0_f32;
        let prev = 0.5_f32;
        let out = ProgressComputer::compute_ema(cur, prev, a);
        assert!((out - (a * cur + (1.0 - a) * prev)).abs() < 1e-5);
    }

    #[test]
    fn stall_when_delta_small() {
        assert!(ProgressComputer::is_stall(0.0, 0.02));
        assert!(ProgressComputer::is_stall(0.01, 0.02));
        assert!(!ProgressComputer::is_stall(0.02, 0.02));
        assert!(!ProgressComputer::is_stall(0.05, 0.02));
    }

    #[test]
    fn regression_when_below_threshold() {
        assert!(ProgressComputer::is_regression(-0.06, -0.05));
        assert!(!ProgressComputer::is_regression(-0.04, -0.05));
        assert!(!ProgressComputer::is_regression(0.1, -0.05));
    }

    #[test]
    fn build_snapshot_fields() {
        let rid = Uuid::nil();
        let s = ProgressComputer::build_snapshot(SnapshotParams {
            run_id: rid,
            step: 7,
            similarity: 0.9,
            delta: 0.01,
            ema_sim: 0.88,
            ema_delta: 0.015,
            stalls: 2,
            model: "test-model",
        });
        assert_eq!(s.run_id, rid);
        assert_eq!(s.step_index, 7);
        assert!((s.similarity - 0.9).abs() < 1e-6);
        assert_eq!(s.embedding_model_revision, "test-model");
        assert_eq!(s.consecutive_stalls, 2);
    }
}

#[cfg(test)]
mod proptest_progress {
    use super::ProgressComputer;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn ema_finite_for_valid_alpha(
            cur in -50f32..50f32,
            prev in -50f32..50f32,
            alpha_numer in 1u32..=1000u32,
        ) {
            let alpha = alpha_numer as f32 / 1000.0;
            let out = ProgressComputer::compute_ema(cur, prev, alpha);
            prop_assert!(out.is_finite());
        }

        #[test]
        fn delta_is_subtraction(a in -1f32..1f32, b in -1f32..1f32) {
            let d = ProgressComputer::compute_delta(a, b);
            prop_assert!((d - (a - b)).abs() < 1e-4);
        }

        #[test]
        fn stall_symmetric_for_opposite_signs(mag in 0f32..0.5f32, t in 0.01f32..0.5f32) {
            prop_assume!(mag < t);
            prop_assert!(ProgressComputer::is_stall(mag, t));
            prop_assert!(ProgressComputer::is_stall(-mag, t));
        }
    }
}
