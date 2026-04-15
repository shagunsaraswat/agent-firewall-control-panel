-- Agent FirewallKit ClickHouse: raw span events (ReplacingMergeTree dedup by event_time).
-- Aligned with final_prd/09-data-models.md §2.1.

CREATE TABLE IF NOT EXISTS spans
(
  event_date Date DEFAULT toDate(event_time),
  event_time DateTime64(3, 'UTC'),
  event_id UUID,
  tenant_id UUID,
  run_id UUID,
  span_id UUID,
  parent_span_id Nullable(UUID),
  trace_id UUID,
  service_name LowCardinality(String),
  span_name LowCardinality(String),
  kind LowCardinality(String),
  duration_ms UInt64,
  status_code LowCardinality(String),
  policy_decision LowCardinality(String),
  reason_code LowCardinality(String),
  tool_name Nullable(String),
  model_name Nullable(String),
  cost_usd Decimal(18, 6),
  attributes String
)
ENGINE = ReplacingMergeTree(event_time)
PARTITION BY toYYYYMM(event_date)
ORDER BY (tenant_id, run_id, event_id, event_time)
TTL event_date + toIntervalDay(180)
SETTINGS index_granularity = 8192;
