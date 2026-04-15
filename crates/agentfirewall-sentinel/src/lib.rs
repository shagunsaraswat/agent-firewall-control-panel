//! Goal-aware progress tracking: embedding similarity, stalls, regressions, and interventions.
//!
//! The main entry point is [`tracker::SentinelTracker`], configured via [`config::SentinelConfig`].

pub mod config;
pub mod intervention;
pub mod progress;
pub mod tracker;

pub use agentfirewall_core::{InterventionLevel, ProgressSnapshot, ReasonCode};
pub use config::{ConfigError, SentinelConfig};
pub use intervention::{InterventionEngine, InterventionSignal};
pub use progress::ProgressComputer;
pub use tracker::{MockSentinelEmbedder, SentinelError, SentinelTracker, StepEvaluation};
