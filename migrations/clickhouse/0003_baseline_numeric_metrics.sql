-- Extended numeric baseline metrics (mean/stddev per run) for deviation checks.

ALTER TABLE behavioral_baselines ADD COLUMN IF NOT EXISTS avg_tool_calls Float64 DEFAULT 0;
ALTER TABLE behavioral_baselines ADD COLUMN IF NOT EXISTS stddev_tool_calls Float64 DEFAULT 0;
ALTER TABLE behavioral_baselines ADD COLUMN IF NOT EXISTS avg_model_calls Float64 DEFAULT 0;
ALTER TABLE behavioral_baselines ADD COLUMN IF NOT EXISTS stddev_model_calls Float64 DEFAULT 0;
ALTER TABLE behavioral_baselines ADD COLUMN IF NOT EXISTS stddev_cost Float64 DEFAULT 0;
ALTER TABLE behavioral_baselines ADD COLUMN IF NOT EXISTS avg_duration_ms Float64 DEFAULT 0;
ALTER TABLE behavioral_baselines ADD COLUMN IF NOT EXISTS stddev_duration_ms Float64 DEFAULT 0;
