use bytes::Bytes;
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NatsError {
    #[error("serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("nats publish failed: {0}")]
    Publish(String),
}

#[derive(Clone)]
pub struct NatsPublisher {
    client: async_nats::Client,
}

impl NatsPublisher {
    pub fn new(client: async_nats::Client) -> Self {
        Self { client }
    }

    pub async fn publish(&self, subject: &str, payload: &impl Serialize) -> Result<(), NatsError> {
        let bytes = serde_json::to_vec(payload)?;
        self.publish_bytes(subject, &bytes).await
    }

    pub async fn publish_bytes(&self, subject: &str, data: &[u8]) -> Result<(), NatsError> {
        self.client
            .publish(subject.to_string(), Bytes::copy_from_slice(data))
            .await
            .map_err(|e| NatsError::Publish(e.to_string()))?;
        Ok(())
    }
}

/// Builds `agentfirewall.{tenant_id}.{domain}.{action}` (e.g. `agentfirewall.{uuid}.approval.requested`).
pub fn subject(tenant_id: &str, domain: &str, action: &str) -> String {
    format!("agentfirewall.{tenant_id}.{domain}.{action}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_format() {
        assert_eq!(
            subject("t1", "approval", "requested"),
            "agentfirewall.t1.approval.requested"
        );
    }
}
