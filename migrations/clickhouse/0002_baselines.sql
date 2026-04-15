-- Agent FirewallKit ClickHouse: per-run aggregates (MV) + behavioral_baselines table.
-- Aligned with final_prd/09-data-models.md §2.2 and §2.6.

CREATE TABLE IF NOT EXISTS run_stats
(
  stats_month Date,
  tenant_id UUID,
  run_id UUID,
  span_count AggregateFunction(sum, UInt64),
  error_span_count AggregateFunction(sum, UInt64),
  total_cost_usd AggregateFunction(sum, Decimal(18, 6)),
  first_event_time SimpleAggregateFunction(min, DateTime64(3, 'UTC')),
  last_event_time SimpleAggregateFunction(max, DateTime64(3, 'UTC')),
  uniq_tools AggregateFunction(uniqExact, String)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(stats_month)
ORDER BY (tenant_id, run_id, stats_month)
TTL stats_month + toIntervalDay(400);

CREATE MATERIALIZED VIEW IF NOT EXISTS run_stats_mv TO run_stats AS
SELECT
  toStartOfMonth(toDate(event_time)) AS stats_month,
  tenant_id,
  run_id,
  sumState(toUInt64(1)) AS span_count,
  sumState(toUInt64(if(status_code = 'ERROR', 1, 0))) AS error_span_count,
  sumState(cost_usd) AS total_cost_usd,
  minSimpleState(event_time) AS first_event_time,
  maxSimpleState(event_time) AS last_event_time,
  uniqExactState(coalesce(tool_name, '')) AS uniq_tools
FROM spans
GROUP BY
  stats_month,
  tenant_id,
  run_id;

CREATE TABLE IF NOT EXISTS behavioral_baselines
(
  bucket_date Date,
  tenant_id UUID,
  agent_type LowCardinality(String),
  baseline_version UInt32 DEFAULT 1,
  tool_entropy Float32,
  top_tools Array(String),
  loop_rate Float32,
  avg_cost_per_run Float32,
  sample_runs UInt64,
  updated_at DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY toYYYYMM(bucket_date)
ORDER BY (tenant_id, agent_type, baseline_version, bucket_date)
TTL bucket_date + toIntervalDay(730);
