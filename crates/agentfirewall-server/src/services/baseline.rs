//! ClickHouse → baseline aggregates, Redis cache, and deviation helpers.

use std::collections::HashMap;
use std::time::Duration;

use agentfirewall_core::types::BehavioralBaseline;
use chrono::Utc;
use redis::AsyncCommands;
use sqlx::PgPool;
use tracing::warn;
use uuid::Uuid;

/// Per-run counters used for z-score style checks against a baseline.
#[derive(Debug, Clone, PartialEq)]
pub struct RunStats {
    pub tool_calls: f64,
    pub model_calls: f64,
    pub cost_usd: f64,
    pub duration_ms: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeviationAlert {
    pub metric: String,
    pub expected_range: (f64, f64),
    pub actual: f64,
    pub sigma_distance: f64,
}

/// Returns alerts for metrics whose absolute z-score exceeds `sigma` (using baseline stddev).
#[must_use]
pub fn check_deviation(
    baseline: &BehavioralBaseline,
    current_run_stats: &RunStats,
    sigma: f64,
) -> Vec<DeviationAlert> {
    let mut out = Vec::new();
    let pairs = [
        (
            "tool_calls",
            current_run_stats.tool_calls,
            baseline.avg_tool_calls,
            baseline.stddev_tool_calls,
        ),
        (
            "model_calls",
            current_run_stats.model_calls,
            baseline.avg_model_calls,
            baseline.stddev_model_calls,
        ),
        (
            "cost_usd",
            current_run_stats.cost_usd,
            f64::from(baseline.avg_cost_per_run),
            baseline.stddev_cost,
        ),
        (
            "duration_ms",
            current_run_stats.duration_ms,
            baseline.avg_duration_ms,
            baseline.stddev_duration_ms,
        ),
    ];
    for (name, actual, mean, stddev) in pairs {
        let stddev = stddev.max(1e-9);
        let z = (actual - mean).abs() / stddev;
        if z > sigma {
            let low = mean - sigma * stddev;
            let high = mean + sigma * stddev;
            out.push(DeviationAlert {
                metric: name.to_owned(),
                expected_range: (low, high),
                actual,
                sigma_distance: z,
            });
        }
    }
    out
}

#[derive(Clone)]
pub struct ClickHouseHttp {
    client: reqwest::Client,
    base_url: String,
}

impl ClickHouseHttp {
    #[must_use]
    pub fn new(base_url: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.trim_end_matches('/').to_owned(),
        }
    }

    async fn query_json(&self, sql: &str) -> Result<serde_json::Value, String> {
        let url = format!("{}/", self.base_url);
        let res = self
            .client
            .post(&url)
            .query(&[("query", sql)])
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !res.status().is_success() {
            return Err(res.text().await.unwrap_or_default());
        }
        let v: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;
        Ok(v)
    }

    async fn insert_json_each_row(&self, sql: &str, body: String) -> Result<(), String> {
        let url = format!("{}/", self.base_url);
        let res = self
            .client
            .post(&url)
            .query(&[("query", sql)])
            .body(body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !res.status().is_success() {
            return Err(res.text().await.unwrap_or_default());
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct RunAggRow {
    tenant_id: String,
    agent_type: String,
    tool_calls: f64,
    model_calls: f64,
    cost: f64,
    duration_ms: f64,
}

#[derive(Debug, serde::Deserialize)]
struct ChJsonResponse {
    data: Vec<serde_json::Map<String, serde_json::Value>>,
}

fn parse_run_rows(v: serde_json::Value) -> Result<Vec<RunAggRow>, String> {
    let wrapped: ChJsonResponse = serde_json::from_value(v).map_err(|e| e.to_string())?;
    let mut rows = Vec::new();
    for m in wrapped.data {
        let tenant_id = m
            .get("tenant_id")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_owned();
        let agent_type = m
            .get("agent_type")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_owned();
        let tool_calls = m.get("tool_calls").and_then(|x| x.as_f64()).unwrap_or(0.0);
        let model_calls = m.get("model_calls").and_then(|x| x.as_f64()).unwrap_or(0.0);
        let cost = m.get("cost").and_then(|x| x.as_f64()).unwrap_or(0.0);
        let duration_ms = m.get("duration_ms").and_then(|x| x.as_f64()).unwrap_or(0.0);
        rows.push(RunAggRow {
            tenant_id,
            agent_type,
            tool_calls,
            model_calls,
            cost,
            duration_ms,
        });
    }
    Ok(rows)
}

fn mean_std(samples: &[f64]) -> (f64, f64) {
    let n = samples.len() as f64;
    if samples.is_empty() {
        return (0.0, 0.0);
    }
    let mean = samples.iter().sum::<f64>() / n;
    if samples.len() < 2 {
        return (mean, 0.0);
    }
    let var = samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0);
    (mean, var.sqrt())
}

async fn run_aggregation_tick(ch: &ClickHouseHttp, redis: &redis::aio::ConnectionManager) {
    let sql = r#"SELECT
      toString(tenant_id) AS tenant_id,
      service_name AS agent_type,
      toString(run_id) AS run_id,
      toFloat64(countIf(kind = 'tool_call')) AS tool_calls,
      toFloat64(countIf(kind = 'model_call')) AS model_calls,
      toFloat64(sum(cost_usd)) AS cost,
      toFloat64(dateDiff('millisecond', min(event_time), max(event_time))) AS duration_ms
    FROM spans
    WHERE event_time >= now() - INTERVAL 24 HOUR
      AND service_name != ''
    GROUP BY tenant_id, service_name, run_id
    FORMAT JSON"#;
    let json = match ch.query_json(sql).await {
        Ok(j) => j,
        Err(e) => {
            warn!(error = %e, "clickhouse baseline query failed; will retry next interval");
            return;
        }
    };
    let rows = match parse_run_rows(json) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "clickhouse baseline JSON parse failed");
            return;
        }
    };
    let mut groups: HashMap<(String, String), Vec<RunAggRow>> = HashMap::new();
    for r in rows {
        if r.agent_type.is_empty() {
            continue;
        }
        groups
            .entry((r.tenant_id.clone(), r.agent_type.clone()))
            .or_default()
            .push(r);
    }
    let now = Utc::now();
    let bucket_date = now.date_naive();
    for ((tenant_s, agent_type), runs) in groups {
        let Ok(tenant_id) = Uuid::parse_str(&tenant_s) else {
            continue;
        };
        let tc: Vec<f64> = runs.iter().map(|r| r.tool_calls).collect();
        let mc: Vec<f64> = runs.iter().map(|r| r.model_calls).collect();
        let costs: Vec<f64> = runs.iter().map(|r| r.cost).collect();
        let durs: Vec<f64> = runs.iter().map(|r| r.duration_ms).collect();
        let (avg_tool_calls, stddev_tool_calls) = mean_std(&tc);
        let (avg_model_calls, stddev_model_calls) = mean_std(&mc);
        let (avg_cost, stddev_cost) = mean_std(&costs);
        let (avg_duration_ms, stddev_duration_ms) = mean_std(&durs);
        let sample_runs = runs.len() as u64;
        let tool_entropy = stddev_tool_calls.max(1e-9).ln() as f32;
        let loop_rate = (stddev_duration_ms / avg_duration_ms.max(1.0)) as f32;
        let baseline = BehavioralBaseline {
            bucket_date,
            tenant_id,
            agent_type: agent_type.clone(),
            baseline_version: 1,
            tool_entropy,
            top_tools: vec![],
            loop_rate,
            avg_cost_per_run: avg_cost as f32,
            sample_runs,
            updated_at: now,
            avg_tool_calls,
            stddev_tool_calls,
            avg_model_calls,
            stddev_model_calls,
            stddev_cost,
            avg_duration_ms,
            stddev_duration_ms,
        };
        let row = serde_json::json!({
            "bucket_date": bucket_date.format("%Y-%m-%d").to_string(),
            "tenant_id": tenant_id.to_string(),
            "agent_type": agent_type,
            "baseline_version": 1u32,
            "tool_entropy": tool_entropy,
            "top_tools": Vec::<String>::new(),
            "loop_rate": loop_rate,
            "avg_cost_per_run": avg_cost as f32,
            "sample_runs": sample_runs,
            "avg_tool_calls": avg_tool_calls,
            "stddev_tool_calls": stddev_tool_calls,
            "avg_model_calls": avg_model_calls,
            "stddev_model_calls": stddev_model_calls,
            "stddev_cost": stddev_cost,
            "avg_duration_ms": avg_duration_ms,
            "stddev_duration_ms": stddev_duration_ms,
            "updated_at": now.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
        });
        let insert_sql = "INSERT INTO behavioral_baselines FORMAT JSONEachRow";
        let body = format!("{}\n", serde_json::to_string(&row).unwrap_or_default());
        if let Err(e) = ch.insert_json_each_row(insert_sql, body).await {
            warn!(
                error = %e,
                tenant_id = %tenant_id,
                agent_type = %agent_type,
                "clickhouse baseline insert failed"
            );
            continue;
        }
        let key = format!("av:baseline:{tenant_id}");
        let payload = match serde_json::to_string(&baseline) {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "baseline redis serialize failed");
                continue;
            }
        };
        let mut conn = redis.clone();
        if let Err(e) = conn.set::<_, _, ()>(&key, payload).await {
            warn!(error = %e, key = %key, "redis baseline cache failed");
        }
    }
}

/// Periodically recomputes baselines from the last 24h of spans.
pub fn start(
    _pool: PgPool,
    redis: redis::aio::ConnectionManager,
    clickhouse_url: String,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let ch = ClickHouseHttp::new(clickhouse_url);
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            run_aggregation_tick(&ch, &redis).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    #[test]
    fn deviation_detects_high_cost() {
        let baseline = BehavioralBaseline {
            bucket_date: NaiveDate::from_ymd_opt(2026, 4, 5).unwrap(),
            tenant_id: Uuid::nil(),
            agent_type: "a".into(),
            baseline_version: 1,
            tool_entropy: 0.0,
            top_tools: vec![],
            loop_rate: 0.0,
            avg_cost_per_run: 1.0,
            sample_runs: 10,
            updated_at: Utc::now(),
            avg_tool_calls: 5.0,
            stddev_tool_calls: 1.0,
            avg_model_calls: 2.0,
            stddev_model_calls: 0.5,
            stddev_cost: 0.2,
            avg_duration_ms: 1000.0,
            stddev_duration_ms: 100.0,
        };
        let run = RunStats {
            tool_calls: 5.0,
            model_calls: 2.0,
            cost_usd: 3.0,
            duration_ms: 1000.0,
        };
        let alerts = check_deviation(&baseline, &run, 3.0);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].metric, "cost_usd");
        assert!(alerts[0].sigma_distance > 3.0);
    }

    #[test]
    fn deviation_empty_when_within_sigma() {
        let baseline = BehavioralBaseline {
            bucket_date: NaiveDate::from_ymd_opt(2026, 4, 5).unwrap(),
            tenant_id: Uuid::nil(),
            agent_type: "a".into(),
            baseline_version: 1,
            tool_entropy: 0.0,
            top_tools: vec![],
            loop_rate: 0.0,
            avg_cost_per_run: 1.0,
            sample_runs: 10,
            updated_at: Utc::now(),
            avg_tool_calls: 5.0,
            stddev_tool_calls: 2.0,
            avg_model_calls: 2.0,
            stddev_model_calls: 1.0,
            stddev_cost: 0.5,
            avg_duration_ms: 1000.0,
            stddev_duration_ms: 200.0,
        };
        let run = RunStats {
            tool_calls: 5.0,
            model_calls: 2.0,
            cost_usd: 1.0,
            duration_ms: 1000.0,
        };
        let alerts = check_deviation(&baseline, &run, 3.0);
        assert!(alerts.is_empty());
    }
}
