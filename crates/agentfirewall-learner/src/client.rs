//! SDK-side learner client: publishes span events to NATS.

use std::sync::{Arc, Mutex};

use agentfirewall_core::types::{LearnerMode, SpanEvent};
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::error::LearnerError;
use crate::mode::LearnerModeManager;

/// Configuration for [`LearnerClient`].
#[derive(Debug, Clone)]
pub struct LearnerClientConfig {
    pub nats_url: String,
    pub subject_prefix: String,
    pub tenant_id: String,
    pub sample_rate: f32,
    pub publish_queue_capacity: usize,
    pub max_span_bytes: usize,
}

impl Default for LearnerClientConfig {
    fn default() -> Self {
        Self {
            nats_url: "nats://localhost:4222".into(),
            subject_prefix: "agentfirewall".into(),
            tenant_id: String::new(),
            sample_rate: 1.0,
            publish_queue_capacity: 1024,
            max_span_bytes: 65536,
        }
    }
}

impl LearnerClientConfig {
    pub fn validate(&self) -> Result<(), LearnerError> {
        if self.nats_url.trim().is_empty() {
            return Err(LearnerError::InvalidConfig(
                "nats_url must not be empty".into(),
            ));
        }
        if self.subject_prefix.trim().is_empty() {
            return Err(LearnerError::InvalidConfig(
                "subject_prefix must not be empty".into(),
            ));
        }
        if self.tenant_id.trim().is_empty() {
            return Err(LearnerError::InvalidConfig(
                "tenant_id must not be empty".into(),
            ));
        }
        if !self.sample_rate.is_finite() || !(0.0..=1.0).contains(&self.sample_rate) {
            return Err(LearnerError::InvalidConfig(format!(
                "sample_rate must be finite and in [0.0, 1.0], got {}",
                self.sample_rate
            )));
        }
        if self.publish_queue_capacity == 0 {
            return Err(LearnerError::InvalidConfig(
                "publish_queue_capacity must be > 0".into(),
            ));
        }
        if self.max_span_bytes == 0 {
            return Err(LearnerError::InvalidConfig(
                "max_span_bytes must be > 0".into(),
            ));
        }
        Ok(())
    }
}

fn ingest_subject(cfg: &LearnerClientConfig) -> String {
    format!(
        "{}.{}.spans.event.ingest.v1",
        cfg.subject_prefix, cfg.tenant_id
    )
}

struct Inner {
    config: LearnerClientConfig,
    mode: LearnerModeManager,
    /// `None` after shutdown.
    work_tx: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
    /// Receiver handed to the publisher exactly once.
    rx_slot: Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
    join: Mutex<Option<JoinHandle<()>>>,
}

/// Handle for emitting learner spans to NATS (observe-to-enforce pipeline).
#[derive(Clone)]
pub struct LearnerClient {
    inner: Arc<Inner>,
}

impl LearnerClient {
    pub fn new(config: LearnerClientConfig) -> Result<Self, LearnerError> {
        config.validate()?;
        let cap = config.publish_queue_capacity;
        let (work_tx, work_rx) = mpsc::channel::<Vec<u8>>(cap);
        Ok(Self {
            inner: Arc::new(Inner {
                config,
                mode: LearnerModeManager::new(LearnerMode::ObserveOnly),
                work_tx: Mutex::new(Some(work_tx)),
                rx_slot: Mutex::new(Some(work_rx)),
                join: Mutex::new(None),
            }),
        })
    }

    /// Connects to NATS and starts the background publisher task.
    pub async fn connect(&self) -> Result<(), LearnerError> {
        let rx = {
            let mut slot = self.inner.rx_slot.lock().unwrap();
            slot.take()
        };
        let Some(rx) = rx else {
            return Ok(());
        };

        let client = async_nats::connect(self.inner.config.nats_url.as_str())
            .await
            .map_err(|e| LearnerError::ConnectionFailed(e.to_string()))?;

        let cfg = self.inner.config.clone();
        let subject = ingest_subject(&cfg);
        let join = tokio::spawn(run_publisher(client, cfg, subject, rx));

        let mut jg = self.inner.join.lock().unwrap();
        *jg = Some(join);
        Ok(())
    }

    /// Non-blocking span emission: sampling, size check, then bounded queue with backpressure.
    ///
    /// Returns `Ok(())` when the span is accepted, sampled out, or dropped due to a full queue.
    pub fn emit_span(&self, span: SpanEvent) -> Result<(), LearnerError> {
        self.ensure_publisher_started()?;

        let payload = serde_json::to_vec(&span).map_err(|e| {
            LearnerError::PublishFailed(format!("span JSON serialization failed: {e}"))
        })?;
        let len = payload.len();
        if len > self.inner.config.max_span_bytes {
            return Err(LearnerError::SpanTooLarge {
                size: len,
                max: self.inner.config.max_span_bytes,
            });
        }

        if !sample_allows(self.inner.config.sample_rate) {
            return Ok(());
        }

        let tx = {
            let g = self.inner.work_tx.lock().unwrap();
            g.as_ref().cloned()
        };
        let Some(tx) = tx else {
            return Err(LearnerError::NotConnected);
        };

        match tx.try_send(payload) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!(
                    target: "agentfirewall_learner",
                    event = "learner_channel_full",
                    capacity = self.inner.config.publish_queue_capacity,
                    "learner publish queue full; dropping span"
                );
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err(LearnerError::NotConnected),
        }
    }

    #[must_use]
    pub fn mode(&self) -> LearnerMode {
        self.inner.mode.current()
    }

    pub fn set_mode(&self, mode: LearnerMode) -> Result<LearnerMode, LearnerError> {
        self.inner.mode.set(mode)
    }

    /// Stops the publisher, closes the queue, and waits for the background task.
    pub async fn shutdown(&self) -> Result<(), LearnerError> {
        {
            let mut tg = self.inner.work_tx.lock().unwrap();
            *tg = None;
        }
        let join = self.inner.join.lock().unwrap().take();
        if let Some(j) = join {
            j.await
                .map_err(|_| LearnerError::PublishFailed("publisher task panicked".into()))?;
        }
        Ok(())
    }

    fn ensure_publisher_started(&self) -> Result<(), LearnerError> {
        let handle = match Handle::try_current() {
            Ok(h) => h,
            Err(_) => {
                if self.inner.join.lock().unwrap().is_some() {
                    return Ok(());
                }
                return Err(LearnerError::NotConnected);
            }
        };

        let rx = {
            let mut slot = self.inner.rx_slot.lock().unwrap();
            slot.take()
        };
        let Some(rx) = rx else {
            return Ok(());
        };

        let cfg = self.inner.config.clone();
        let subject = ingest_subject(&cfg);
        let join = handle.spawn(async move {
            let client = match async_nats::connect(cfg.nats_url.as_str()).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(
                        target: "agentfirewall_learner",
                        error = %e,
                        "learner: NATS connection failed (lazy start)"
                    );
                    return;
                }
            };
            run_publisher(client, cfg, subject, rx).await;
        });

        let mut jg = self.inner.join.lock().unwrap();
        *jg = Some(join);
        Ok(())
    }
}

fn sample_allows(rate: f32) -> bool {
    if rate >= 1.0 {
        return true;
    }
    if rate <= 0.0 {
        return false;
    }
    let u = uuid::Uuid::new_v4();
    let b = u.as_bytes()[0];
    (b as f32) / 255.0 < rate
}

async fn run_publisher(
    client: async_nats::Client,
    _cfg: LearnerClientConfig,
    subject: String,
    mut rx: mpsc::Receiver<Vec<u8>>,
) {
    while let Some(payload) = rx.recv().await {
        if let Err(e) = client.publish(subject.clone(), payload.into()).await {
            tracing::error!(
                target: "agentfirewall_learner",
                error = %e,
                subject = %subject,
                "learner: NATS publish failed"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentfirewall_core::types::SpanEvent;
    use chrono::Utc;
    use std::collections::HashMap;
    use uuid::Uuid;

    fn minimal_span() -> SpanEvent {
        SpanEvent {
            event_id: Uuid::new_v4(),
            trace_id: "t".into(),
            span_id: "s".into(),
            parent_span_id: None,
            ts: Utc::now(),
            tenant_id: Uuid::new_v4(),
            workspace_id: None,
            project_id: None,
            agent_type: String::new(),
            agent_id: Uuid::nil(),
            task_category: String::new(),
            run_id: Uuid::new_v4(),
            kind: "run_start".into(),
            tool_name: String::new(),
            tool_args_fingerprint: String::new(),
            model_id: String::new(),
            cost_usd: 0.0,
            input_tokens: 0,
            output_tokens: 0,
            step_index: 0,
            progress_score: 0.0,
            progress_delta: 0.0,
            write_target_uri: String::new(),
            write_operation: String::new(),
            net_host: String::new(),
            net_method: String::new(),
            attributes: HashMap::new(),
            sdk_version: String::new(),
        }
    }

    #[test]
    fn config_validation_ok() {
        let c = LearnerClientConfig {
            tenant_id: "t1".into(),
            ..LearnerClientConfig::default()
        };
        c.validate().unwrap();
    }

    #[test]
    fn config_rejects_empty_tenant() {
        let c = LearnerClientConfig::default();
        assert!(matches!(c.validate(), Err(LearnerError::InvalidConfig(_))));
    }

    #[test]
    fn config_rejects_bad_sample_rate() {
        let mut c = LearnerClientConfig {
            tenant_id: "x".into(),
            ..LearnerClientConfig::default()
        };
        c.sample_rate = 1.5;
        assert!(c.validate().is_err());
        c.sample_rate = f32::NAN;
        assert!(c.validate().is_err());
    }

    #[test]
    fn client_new_without_nats() {
        let c = LearnerClientConfig {
            tenant_id: "acme".into(),
            ..LearnerClientConfig::default()
        };
        let client = LearnerClient::new(c).unwrap();
        assert_eq!(client.mode(), LearnerMode::ObserveOnly);
    }

    #[test]
    fn ingest_subject_format() {
        let c = LearnerClientConfig {
            tenant_id: "acme".into(),
            subject_prefix: "agentfirewall".into(),
            ..LearnerClientConfig::default()
        };
        assert_eq!(ingest_subject(&c), "agentfirewall.acme.spans.event.ingest.v1");
    }

    #[tokio::test]
    async fn emit_before_connect_requires_runtime() {
        let c = LearnerClientConfig {
            tenant_id: "acme".into(),
            ..LearnerClientConfig::default()
        };
        let client = LearnerClient::new(c).unwrap();
        let r = client.emit_span(minimal_span());
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn shutdown_idempotent_client() {
        let c = LearnerClientConfig {
            tenant_id: "acme".into(),
            publish_queue_capacity: 4,
            ..LearnerClientConfig::default()
        };
        let client = LearnerClient::new(c).unwrap();
        client.shutdown().await.unwrap();
        let err = client.emit_span(minimal_span());
        assert!(matches!(err, Err(LearnerError::NotConnected)));
    }

    #[tokio::test]
    async fn mpsc_backpressure_drops_when_full() {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(2);
        assert!(tx.try_send(vec![1]).is_ok());
        assert!(tx.try_send(vec![2]).is_ok());
        assert!(tx.try_send(vec![3]).is_err());
        let _ = rx.recv().await;
        assert!(tx.try_send(vec![4]).is_ok());
    }

    #[tokio::test]
    async fn emit_span_too_large_returns_error() {
        let c = LearnerClientConfig {
            tenant_id: "acme".into(),
            max_span_bytes: 16,
            ..LearnerClientConfig::default()
        };
        let client = LearnerClient::new(c).unwrap();
        let mut span = minimal_span();
        span.attributes.insert("big".into(), "x".repeat(100));
        let err = client.emit_span(span).unwrap_err();
        assert!(matches!(err, LearnerError::SpanTooLarge { .. }));
    }
}
