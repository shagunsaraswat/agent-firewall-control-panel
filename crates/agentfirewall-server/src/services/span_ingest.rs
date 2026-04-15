//! NATS → ClickHouse span ingestion with batching and JSONEachRow HTTP inserts.

use std::time::Duration;

use agentfirewall_core::types::SpanEvent;
use chrono::{DateTime, SecondsFormat, Utc};
use futures_util::stream::StreamExt;
use serde::Serialize;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::{error, warn};
use uuid::Uuid;

/// One row for the `spans` ClickHouse table (`migrations/clickhouse/0001_spans.sql`).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SpanRow {
    pub event_time: String,
    pub event_id: Uuid,
    pub tenant_id: Uuid,
    pub run_id: Uuid,
    pub span_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<Uuid>,
    pub trace_id: Uuid,
    pub service_name: String,
    pub span_name: String,
    pub kind: String,
    pub duration_ms: u64,
    pub status_code: String,
    pub policy_decision: String,
    pub reason_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_name: Option<String>,
    pub cost_usd: String,
    pub attributes: String,
}

impl SpanRow {
    #[must_use]
    pub fn from_span_event(ev: &SpanEvent) -> Option<Self> {
        if ev.tenant_id.is_nil() || ev.run_id.is_nil() || ev.event_id.is_nil() {
            return None;
        }
        let span_id = parse_uuid_loose(&ev.span_id).unwrap_or_else(Uuid::nil);
        let trace_id = parse_uuid_loose(&ev.trace_id).unwrap_or_else(Uuid::nil);
        let parent_span_id = ev
            .parent_span_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .and_then(parse_uuid_loose);
        let service_name = if ev.agent_type.trim().is_empty() {
            "agentfirewall".to_owned()
        } else {
            ev.agent_type.clone()
        };
        let span_name = if !ev.tool_name.is_empty() {
            ev.tool_name.clone()
        } else if !ev.kind.is_empty() {
            ev.kind.clone()
        } else {
            "span".to_owned()
        };
        let tool_name = empty_none(&ev.tool_name);
        let model_name = empty_none(&ev.model_id);
        let cost = format!("{:.6}", ev.cost_usd);
        let attrs = serde_json::to_string(&ev.attributes).unwrap_or_else(|_| "{}".to_owned());
        Some(Self {
            event_time: format_ch_datetime(ev.ts),
            event_id: ev.event_id,
            tenant_id: ev.tenant_id,
            run_id: ev.run_id,
            span_id,
            parent_span_id,
            trace_id,
            service_name,
            span_name,
            kind: ev.kind.clone(),
            duration_ms: 0,
            status_code: "OK".to_owned(),
            policy_decision: "".to_owned(),
            reason_code: "".to_owned(),
            tool_name,
            model_name,
            cost_usd: cost,
            attributes: attrs,
        })
    }
}

fn empty_none(s: &str) -> Option<String> {
    if s.trim().is_empty() {
        None
    } else {
        Some(s.to_owned())
    }
}

fn parse_uuid_loose(s: &str) -> Option<Uuid> {
    if s.is_empty() {
        return None;
    }
    if let Ok(u) = Uuid::parse_str(s) {
        return Some(u);
    }
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() == 32 {
        Uuid::parse_str(&format!(
            "{}-{}-{}-{}-{}",
            &hex[0..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..32]
        ))
        .ok()
    } else {
        None
    }
}

fn format_ch_datetime(ts: DateTime<Utc>) -> String {
    ts.to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[derive(Debug, Error)]
pub enum ClickHouseError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("clickhouse error: {0}")]
    Server(String),
}

#[derive(Clone)]
pub struct ClickHouseWriter {
    client: reqwest::Client,
    base_url: String,
}

impl ClickHouseWriter {
    #[must_use]
    pub fn new(base_url: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.trim_end_matches('/').to_owned(),
        }
    }

    /// `INSERT` into `spans` using JSONEachRow over the HTTP interface.
    pub async fn insert_spans(&self, spans: &[SpanRow]) -> Result<(), ClickHouseError> {
        if spans.is_empty() {
            return Ok(());
        }
        match self.insert_spans_inner(spans).await {
            Ok(()) => Ok(()),
            Err(e) => {
                warn!(error = %e, "clickhouse insert failed, retrying once");
                self.insert_spans_inner(spans).await
            }
        }
    }

    async fn insert_spans_inner(&self, spans: &[SpanRow]) -> Result<(), ClickHouseError> {
        let mut body = String::new();
        for row in spans {
            body.push_str(
                &serde_json::to_string(row)
                    .map_err(|e| ClickHouseError::Server(format!("serialize span row: {e}")))?,
            );
            body.push('\n');
        }
        let url = format!("{}/", self.base_url);
        let res = self
            .client
            .post(&url)
            .query(&[("query", "INSERT INTO spans FORMAT JSONEachRow")])
            .body(body)
            .send()
            .await?;
        if !res.status().is_success() {
            let text = res.text().await.unwrap_or_default();
            return Err(ClickHouseError::Server(text));
        }
        Ok(())
    }
}

fn validate_span_event(ev: &SpanEvent) -> Result<(), &'static str> {
    if ev.event_id.is_nil() {
        return Err("event_id required");
    }
    if ev.tenant_id.is_nil() {
        return Err("tenant_id required");
    }
    if ev.run_id.is_nil() {
        return Err("run_id required");
    }
    Ok(())
}

/// Subscribes to `agentfirewall.*.spans.event.ingest.v1`, batches rows, inserts into ClickHouse.
/// Flushes on interval, when the batch reaches 100 rows, when the subscription ends, or on Ctrl+C.
pub fn start(nats: async_nats::Client, clickhouse_url: String) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run_span_ingest(nats, clickhouse_url, ShutdownSignal::CtrlC).await;
    })
}

enum ShutdownSignal {
    CtrlC,
    Channel(mpsc::Receiver<()>),
}

async fn run_span_ingest(
    nats: async_nats::Client,
    clickhouse_url: String,
    shutdown: ShutdownSignal,
) {
    let writer = ClickHouseWriter::new(clickhouse_url);
    let mut sub = match nats.subscribe("agentfirewall.*.spans.event.ingest.v1").await {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "failed to subscribe to span ingest subject");
            return;
        }
    };
    let mut batch: Vec<SpanRow> = Vec::new();
    let mut last_flush = Instant::now();
    let batch_interval = Duration::from_millis(500);
    let batch_max = 100usize;
    let mut flush_ticker = tokio::time::interval(batch_interval);
    flush_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    match shutdown {
        ShutdownSignal::CtrlC => loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    flush_batch(&writer, &mut batch, &mut last_flush).await;
                    return;
                }
                _ = flush_ticker.tick() => {
                    if !batch.is_empty() && last_flush.elapsed() >= batch_interval {
                        flush_batch(&writer, &mut batch, &mut last_flush).await;
                    }
                }
                maybe = sub.next() => {
                    match ingest_message(maybe, &mut batch, batch_max, &writer, &mut last_flush).await {
                        IngestLoopCtl::Continue => {}
                        IngestLoopCtl::Stop => return,
                    }
                }
            }
        },
        ShutdownSignal::Channel(mut shutdown_rx) => loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    flush_batch(&writer, &mut batch, &mut last_flush).await;
                    return;
                }
                _ = flush_ticker.tick() => {
                    if !batch.is_empty() && last_flush.elapsed() >= batch_interval {
                        flush_batch(&writer, &mut batch, &mut last_flush).await;
                    }
                }
                maybe = sub.next() => {
                    match ingest_message(maybe, &mut batch, batch_max, &writer, &mut last_flush).await {
                        IngestLoopCtl::Continue => {}
                        IngestLoopCtl::Stop => return,
                    }
                }
            }
        },
    }
}

enum IngestLoopCtl {
    Continue,
    Stop,
}

async fn ingest_message(
    maybe: Option<async_nats::Message>,
    batch: &mut Vec<SpanRow>,
    batch_max: usize,
    writer: &ClickHouseWriter,
    last_flush: &mut Instant,
) -> IngestLoopCtl {
    match maybe {
        Some(msg) => {
            let Ok(ev) = serde_json::from_slice::<SpanEvent>(&msg.payload) else {
                warn!("invalid span ingest JSON");
                return IngestLoopCtl::Continue;
            };
            if let Err(reason) = validate_span_event(&ev) {
                warn!(reason, "span validation failed");
                return IngestLoopCtl::Continue;
            }
            let Some(row) = SpanRow::from_span_event(&ev) else {
                warn!("could not map span to ClickHouse row");
                return IngestLoopCtl::Continue;
            };
            batch.push(row);
            if batch.len() >= batch_max {
                flush_batch(writer, batch, last_flush).await;
            }
            IngestLoopCtl::Continue
        }
        None => {
            flush_batch(writer, batch, last_flush).await;
            IngestLoopCtl::Stop
        }
    }
}

async fn flush_batch(
    writer: &ClickHouseWriter,
    batch: &mut Vec<SpanRow>,
    last_flush: &mut Instant,
) {
    if batch.is_empty() {
        return;
    }
    let rows = std::mem::take(batch);
    *last_flush = Instant::now();
    if let Err(e) = writer.insert_spans(&rows).await {
        error!(error = %e, count = rows.len(), "failed to flush span batch");
    }
}

/// Call from shutdown hooks to flush and stop the ingest loop.
#[derive(Clone)]
pub struct SpanIngestShutdown {
    tx: mpsc::Sender<()>,
}

impl SpanIngestShutdown {
    pub fn signal(&self) {
        let _ = self.tx.try_send(());
    }
}

/// Same as [`start`] but returns a handle you can use to request graceful shutdown (flush).
pub fn start_with_shutdown(
    nats: async_nats::Client,
    clickhouse_url: String,
) -> (tokio::task::JoinHandle<()>, SpanIngestShutdown) {
    let (tx, rx) = mpsc::channel(1);
    let handle = tokio::spawn(async move {
        run_span_ingest(nats, clickhouse_url, ShutdownSignal::Channel(rx)).await;
    });
    (handle, SpanIngestShutdown { tx })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use uuid::Uuid;

    #[test]
    fn span_row_json_each_row_shape() {
        let ev = SpanEvent {
            event_id: Uuid::from_u128(1),
            trace_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            span_id: "660e8400-e29b-41d4-a716-446655440001".into(),
            parent_span_id: None,
            ts: Utc.with_ymd_and_hms(2026, 4, 5, 12, 0, 0).unwrap(),
            tenant_id: Uuid::from_u128(2),
            workspace_id: None,
            project_id: None,
            agent_type: "coder".into(),
            agent_id: Uuid::nil(),
            task_category: "fix".into(),
            run_id: Uuid::from_u128(3),
            kind: "tool_call".into(),
            tool_name: "read_file".into(),
            tool_args_fingerprint: "".into(),
            model_id: "".into(),
            cost_usd: 0.001234,
            input_tokens: 0,
            output_tokens: 0,
            step_index: 1,
            progress_score: 0.0,
            progress_delta: 0.0,
            write_target_uri: "".into(),
            write_operation: "".into(),
            net_host: "".into(),
            net_method: "".into(),
            attributes: Default::default(),
            sdk_version: "0.1.0".into(),
        };
        let row = SpanRow::from_span_event(&ev).expect("row");
        let j = serde_json::to_string(&row).unwrap();
        assert!(j.contains(&format!("\"event_id\":\"{}\"", Uuid::from_u128(1))));
        assert!(j.contains("\"service_name\":\"coder\""));
        assert!(j.contains("\"tool_name\":\"read_file\""));
        assert!(j.contains("\"cost_usd\":\"0.001234\""));
    }

    #[test]
    fn from_span_event_rejects_nil_tenant() {
        let mut ev = SpanEvent {
            event_id: Uuid::new_v4(),
            trace_id: "".into(),
            span_id: "".into(),
            parent_span_id: None,
            ts: Utc::now(),
            tenant_id: Uuid::nil(),
            workspace_id: None,
            project_id: None,
            agent_type: "".into(),
            agent_id: Uuid::nil(),
            task_category: "".into(),
            run_id: Uuid::new_v4(),
            kind: "".into(),
            tool_name: "".into(),
            tool_args_fingerprint: "".into(),
            model_id: "".into(),
            cost_usd: 0.0,
            input_tokens: 0,
            output_tokens: 0,
            step_index: 0,
            progress_score: 0.0,
            progress_delta: 0.0,
            write_target_uri: "".into(),
            write_operation: "".into(),
            net_host: "".into(),
            net_method: "".into(),
            attributes: Default::default(),
            sdk_version: "".into(),
        };
        assert!(SpanRow::from_span_event(&ev).is_none());
        ev.tenant_id = Uuid::new_v4();
        assert!(SpanRow::from_span_event(&ev).is_some());
    }
}
