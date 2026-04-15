//! Learner client error types.

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LearnerError {
    #[error("NATS connection failed: {0}")]
    ConnectionFailed(String),

    #[error("NATS publish failed: {0}")]
    PublishFailed(String),

    #[error("learner publish channel is full")]
    ChannelFull,

    #[error("span payload too large: {size} bytes (max {max})")]
    SpanTooLarge { size: usize, max: usize },

    #[error("invalid learner client configuration: {0}")]
    InvalidConfig(String),

    #[error("learner client is not connected to a Tokio runtime")]
    NotConnected,
}
