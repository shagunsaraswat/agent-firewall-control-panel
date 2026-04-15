//! Observe-to-enforce learner client: span emission to NATS for behavioral analysis.

pub mod client;
pub mod error;
pub mod mode;
pub mod span;

pub use client::{LearnerClient, LearnerClientConfig};
pub use error::LearnerError;
pub use mode::{LearnerMode, LearnerModeManager};
pub use span::{RedactionPattern, SpanBuilder, SpanKind, SpanRedactor};
