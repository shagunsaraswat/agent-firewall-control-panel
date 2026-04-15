//! Operational configuration for the Sentinel goal tracker.

use agentfirewall_core::InterventionLevel;
use thiserror::Error;

/// Sentinel runtime settings (distinct from core domain types).
#[derive(Debug, Clone, PartialEq)]
pub struct SentinelConfig {
    pub enabled: bool,
    pub model_id: String,
    pub stall_threshold: f32,
    pub stall_window: u32,
    pub regression_threshold: f32,
    pub max_intervention: InterventionLevel,
    pub max_embed_input_bytes: usize,
    pub ema_alpha: f32,
}

impl Default for SentinelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            model_id: "BAAI/bge-small-en-v1.5".to_string(),
            stall_threshold: 0.02,
            stall_window: 3,
            regression_threshold: -0.05,
            max_intervention: InterventionLevel::Warn,
            max_embed_input_bytes: 8192,
            ema_alpha: 0.3,
        }
    }
}

/// Invalid [`SentinelConfig`] field values.
#[derive(Debug, Error, PartialEq)]
pub enum ConfigError {
    #[error("stall_threshold must be in [0.0, 1.0], got {0}")]
    StallThresholdOutOfRange(f32),
    #[error("stall_window must be >= 1, got {0}")]
    StallWindowTooSmall(u32),
    #[error("regression_threshold must be < 0.0, got {0}")]
    RegressionThresholdNonNegative(f32),
    #[error("ema_alpha must be in (0.0, 1.0], got {0}")]
    EmaAlphaOutOfRange(f32),
    #[error("max_embed_input_bytes must be >= 64, got {0}")]
    MaxEmbedInputTooSmall(usize),
}

impl SentinelConfig {
    /// Validates numeric and structural constraints.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !(self.stall_threshold.is_finite()
            && self.stall_threshold >= 0.0
            && self.stall_threshold <= 1.0)
        {
            return Err(ConfigError::StallThresholdOutOfRange(self.stall_threshold));
        }
        if self.stall_window < 1 {
            return Err(ConfigError::StallWindowTooSmall(self.stall_window));
        }
        if !(self.regression_threshold.is_finite() && self.regression_threshold < 0.0) {
            return Err(ConfigError::RegressionThresholdNonNegative(
                self.regression_threshold,
            ));
        }
        if !(self.ema_alpha.is_finite() && self.ema_alpha > 0.0 && self.ema_alpha <= 1.0) {
            return Err(ConfigError::EmaAlphaOutOfRange(self.ema_alpha));
        }
        if self.max_embed_input_bytes < 64 {
            return Err(ConfigError::MaxEmbedInputTooSmall(
                self.max_embed_input_bytes,
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_validates() {
        let c = SentinelConfig::default();
        c.validate().unwrap();
    }

    #[test]
    fn stall_threshold_bounds() {
        let c = SentinelConfig {
            stall_threshold: -0.01,
            ..SentinelConfig::default()
        };
        assert_eq!(
            c.validate(),
            Err(ConfigError::StallThresholdOutOfRange(-0.01))
        );

        let c = SentinelConfig {
            stall_threshold: 1.1,
            ..SentinelConfig::default()
        };
        assert_eq!(
            c.validate(),
            Err(ConfigError::StallThresholdOutOfRange(1.1))
        );

        let c = SentinelConfig {
            stall_threshold: f32::NAN,
            ..SentinelConfig::default()
        };
        assert!(matches!(
            c.validate(),
            Err(ConfigError::StallThresholdOutOfRange(_))
        ));
    }

    #[test]
    fn stall_window_min() {
        let c = SentinelConfig {
            stall_window: 0,
            ..SentinelConfig::default()
        };
        assert_eq!(c.validate(), Err(ConfigError::StallWindowTooSmall(0)));
    }

    #[test]
    fn regression_must_be_negative() {
        let c = SentinelConfig {
            regression_threshold: 0.0,
            ..SentinelConfig::default()
        };
        assert_eq!(
            c.validate(),
            Err(ConfigError::RegressionThresholdNonNegative(0.0))
        );

        let c = SentinelConfig {
            regression_threshold: 0.01,
            ..SentinelConfig::default()
        };
        assert_eq!(
            c.validate(),
            Err(ConfigError::RegressionThresholdNonNegative(0.01))
        );
    }

    #[test]
    fn ema_alpha_range() {
        let c = SentinelConfig {
            ema_alpha: 0.0,
            ..SentinelConfig::default()
        };
        assert_eq!(c.validate(), Err(ConfigError::EmaAlphaOutOfRange(0.0)));

        let c = SentinelConfig {
            ema_alpha: 1.01,
            ..SentinelConfig::default()
        };
        assert_eq!(c.validate(), Err(ConfigError::EmaAlphaOutOfRange(1.01)));

        let c = SentinelConfig {
            ema_alpha: 1.0,
            ..SentinelConfig::default()
        };
        c.validate().unwrap();
    }

    #[test]
    fn max_embed_input_min() {
        let c = SentinelConfig {
            max_embed_input_bytes: 63,
            ..SentinelConfig::default()
        };
        assert_eq!(c.validate(), Err(ConfigError::MaxEmbedInputTooSmall(63)));
    }
}
