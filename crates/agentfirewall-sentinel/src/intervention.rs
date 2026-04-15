//! Maps progress telemetry to optional intervention signals.

use agentfirewall_core::{InterventionLevel, ProgressSnapshot, ReasonCode};

use crate::config::SentinelConfig;

/// Action recommended when progress rules fire.
#[derive(Debug, Clone, PartialEq)]
pub struct InterventionSignal {
    pub level: InterventionLevel,
    pub reason_code: ReasonCode,
    pub message: String,
    pub snapshot: ProgressSnapshot,
}

/// Evaluates [`ProgressSnapshot`] against [`SentinelConfig`] thresholds.
pub struct InterventionEngine {
    stall_window: u32,
    regression_threshold: f32,
    max_intervention: InterventionLevel,
}

impl InterventionEngine {
    pub fn new(config: &SentinelConfig) -> Self {
        Self {
            stall_window: config.stall_window,
            regression_threshold: config.regression_threshold,
            max_intervention: config.max_intervention,
        }
    }

    /// Returns an intervention when regression or prolonged stall is detected.
    pub fn evaluate(&self, snapshot: &ProgressSnapshot) -> Option<InterventionSignal> {
        if snapshot.ema_delta < self.regression_threshold {
            let level = cap_intervention(InterventionLevel::Deny, self.max_intervention);
            return Some(InterventionSignal {
                level,
                reason_code: ReasonCode::from("PROGRESS_REGRESSION"),
                message: format!(
                    "Smoothed similarity delta {:.4} is below regression threshold {:.4}",
                    snapshot.ema_delta, self.regression_threshold
                ),
                snapshot: snapshot.clone(),
            });
        }

        let stalls = snapshot.consecutive_stalls;
        let w = self.stall_window;
        if stalls < w {
            return None;
        }

        let desired = if stalls >= w * 4 {
            InterventionLevel::Deny
        } else if stalls >= w * 3 {
            InterventionLevel::Pause
        } else if stalls >= w * 2 {
            InterventionLevel::Downgrade
        } else {
            InterventionLevel::Warn
        };

        let level = cap_intervention(desired, self.max_intervention);
        Some(InterventionSignal {
            level,
            reason_code: ReasonCode::from("PROGRESS_STALL"),
            message: format!(
                "No meaningful progress for {} consecutive steps (threshold window {})",
                stalls, w
            ),
            snapshot: snapshot.clone(),
        })
    }
}

fn severity(level: InterventionLevel) -> u8 {
    match level {
        InterventionLevel::Warn => 0,
        InterventionLevel::Downgrade => 1,
        InterventionLevel::Pause => 2,
        InterventionLevel::Deny => 3,
    }
}

/// Picks the less severe of `desired` and `max`, i.e. caps escalation at `max`.
fn cap_intervention(desired: InterventionLevel, max: InterventionLevel) -> InterventionLevel {
    if severity(desired) <= severity(max) {
        desired
    } else {
        max
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SentinelConfig;
    use chrono::Utc;
    use uuid::Uuid;

    fn snap(ema_delta: f32, consecutive_stalls: u32) -> ProgressSnapshot {
        ProgressSnapshot {
            run_id: Uuid::nil(),
            step_index: 1,
            similarity: 0.5,
            delta: ema_delta,
            ema_similarity: 0.5,
            ema_delta,
            consecutive_stalls,
            embedding_model_revision: "m".into(),
            observed_at: Utc::now(),
        }
    }

    #[test]
    fn regression_triggers_deny_capped() {
        let cfg = SentinelConfig {
            max_intervention: InterventionLevel::Downgrade,
            ..SentinelConfig::default()
        };
        let eng = InterventionEngine::new(&cfg);
        let s = snap(-0.1, 0);
        let sig = eng.evaluate(&s).expect("signal");
        assert_eq!(sig.level, InterventionLevel::Downgrade);
        assert_eq!(sig.reason_code.as_str(), "PROGRESS_REGRESSION");
    }

    #[test]
    fn regression_uncapped_deny() {
        let cfg = SentinelConfig {
            max_intervention: InterventionLevel::Deny,
            ..SentinelConfig::default()
        };
        let eng = InterventionEngine::new(&cfg);
        let s = snap(-0.06, 0);
        let sig = eng.evaluate(&s).unwrap();
        assert_eq!(sig.level, InterventionLevel::Deny);
    }

    #[test]
    fn no_signal_when_ok() {
        let eng = InterventionEngine::new(&SentinelConfig::default());
        assert!(eng.evaluate(&snap(0.0, 0)).is_none());
        assert!(eng.evaluate(&snap(0.0, 2)).is_none());
    }

    #[test]
    fn graduated_stall_warn_downgrade_pause_deny() {
        let cfg = SentinelConfig {
            max_intervention: InterventionLevel::Deny,
            ..SentinelConfig::default()
        };
        let eng = InterventionEngine::new(&cfg);
        let w = cfg.stall_window;

        assert_eq!(
            eng.evaluate(&snap(0.0, w)).unwrap().level,
            InterventionLevel::Warn
        );
        assert_eq!(
            eng.evaluate(&snap(0.0, w * 2)).unwrap().level,
            InterventionLevel::Downgrade
        );
        assert_eq!(
            eng.evaluate(&snap(0.0, w * 3)).unwrap().level,
            InterventionLevel::Pause
        );
        assert_eq!(
            eng.evaluate(&snap(0.0, w * 4)).unwrap().level,
            InterventionLevel::Deny
        );
        assert_eq!(
            eng.evaluate(&snap(0.0, w * 10)).unwrap().level,
            InterventionLevel::Deny
        );
    }

    #[test]
    fn stall_capped_at_max_intervention() {
        let cfg = SentinelConfig {
            max_intervention: InterventionLevel::Warn,
            ..SentinelConfig::default()
        };
        let eng = InterventionEngine::new(&cfg);
        let w = cfg.stall_window;
        assert_eq!(
            eng.evaluate(&snap(0.0, w * 4)).unwrap().level,
            InterventionLevel::Warn
        );
    }

    #[test]
    fn regression_takes_priority_over_stall() {
        let eng = InterventionEngine::new(&SentinelConfig::default());
        let s = snap(-0.1, 100);
        let sig = eng.evaluate(&s).unwrap();
        assert_eq!(sig.reason_code.as_str(), "PROGRESS_REGRESSION");
    }
}
