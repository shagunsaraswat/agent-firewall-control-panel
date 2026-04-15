//! Learner mode state machine for the SDK hot path.

use std::sync::atomic::{AtomicU8, Ordering};

pub use agentfirewall_core::types::LearnerMode;

use crate::error::LearnerError;

#[derive(Debug)]
pub struct LearnerModeManager {
    mode: AtomicU8,
}

impl LearnerModeManager {
    #[must_use]
    pub fn new(initial: LearnerMode) -> Self {
        Self {
            mode: AtomicU8::new(mode_to_u8(initial)),
        }
    }

    #[must_use]
    pub fn current(&self) -> LearnerMode {
        u8_to_mode(self.mode.load(Ordering::Acquire)).unwrap_or(LearnerMode::ObserveOnly)
    }

    pub fn set(&self, new_mode: LearnerMode) -> Result<LearnerMode, LearnerError> {
        let prev_u8 = self.mode.swap(mode_to_u8(new_mode), Ordering::AcqRel);
        Ok(u8_to_mode(prev_u8).unwrap_or(LearnerMode::ObserveOnly))
    }

    /// All current modes emit spans to the learner pipeline.
    #[must_use]
    pub fn is_emitting(&self) -> bool {
        true
    }
}

fn mode_to_u8(mode: LearnerMode) -> u8 {
    match mode {
        LearnerMode::ObserveOnly => 0,
        LearnerMode::Recommend => 1,
        LearnerMode::AutoPromoteSafe => 2,
    }
}

fn u8_to_mode(v: u8) -> Option<LearnerMode> {
    match v {
        0 => Some(LearnerMode::ObserveOnly),
        1 => Some(LearnerMode::Recommend),
        2 => Some(LearnerMode::AutoPromoteSafe),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manager_roundtrip_modes() {
        let m = LearnerModeManager::new(LearnerMode::ObserveOnly);
        assert_eq!(m.current(), LearnerMode::ObserveOnly);
        assert!(m.is_emitting());

        let prev = m.set(LearnerMode::Recommend).unwrap();
        assert_eq!(prev, LearnerMode::ObserveOnly);
        assert_eq!(m.current(), LearnerMode::Recommend);

        let prev = m.set(LearnerMode::AutoPromoteSafe).unwrap();
        assert_eq!(prev, LearnerMode::Recommend);
        assert_eq!(m.current(), LearnerMode::AutoPromoteSafe);
    }

    #[test]
    fn transitions_observe_to_recommend_and_auto() {
        let m = LearnerModeManager::new(LearnerMode::ObserveOnly);
        assert_eq!(
            m.set(LearnerMode::Recommend).unwrap(),
            LearnerMode::ObserveOnly
        );
        assert_eq!(
            m.set(LearnerMode::ObserveOnly).unwrap(),
            LearnerMode::Recommend
        );

        assert_eq!(
            m.set(LearnerMode::AutoPromoteSafe).unwrap(),
            LearnerMode::ObserveOnly
        );
        assert_eq!(
            m.set(LearnerMode::ObserveOnly).unwrap(),
            LearnerMode::AutoPromoteSafe
        );
    }

    #[test]
    fn transitions_recommend_auto_rollback_downgrade() {
        let m = LearnerModeManager::new(LearnerMode::Recommend);
        assert_eq!(
            m.set(LearnerMode::AutoPromoteSafe).unwrap(),
            LearnerMode::Recommend
        );
        assert_eq!(
            m.set(LearnerMode::Recommend).unwrap(),
            LearnerMode::AutoPromoteSafe
        );
        assert_eq!(
            m.set(LearnerMode::ObserveOnly).unwrap(),
            LearnerMode::Recommend
        );
        assert_eq!(
            m.set(LearnerMode::Recommend).unwrap(),
            LearnerMode::ObserveOnly
        );
    }

    #[test]
    fn concurrent_reads_remain_consistent() {
        let m = std::sync::Arc::new(LearnerModeManager::new(LearnerMode::ObserveOnly));
        let mut handles = vec![];
        for _ in 0..8 {
            let mm = std::sync::Arc::clone(&m);
            handles.push(std::thread::spawn(move || {
                for _ in 0..1000 {
                    let _ = mm.current();
                    let _ = mm.is_emitting();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert!(m.is_emitting());
    }
}
