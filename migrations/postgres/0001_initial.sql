-- Agent FirewallKit: core transactional schema (policies, runs, steps).
-- Aligned with final_prd/09-data-models.md §1.1–1.2.
-- UUIDv7 IDs are application-assigned (no DB default).

-- Optional: DB-side digest helpers if needed by future migrations
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE OR REPLACE FUNCTION av_set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- policies — logical policy (stable identity across versions)
-- tenant_id: RLS-ready isolation key
-- ---------------------------------------------------------------------------
CREATE TABLE policies (
  id                uuid PRIMARY KEY,
  tenant_id         uuid NOT NULL,
  name              text NOT NULL,
  slug              text NOT NULL,
  description       text,
  created_by        uuid,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  deleted_at        timestamptz,
  CONSTRAINT policies_slug_per_tenant UNIQUE (tenant_id, slug),
  CONSTRAINT policies_name_not_empty CHECK (char_length(btrim(name)) > 0),
  CONSTRAINT policies_slug_not_empty CHECK (char_length(btrim(slug)) > 0)
);

CREATE INDEX policies_tenant_created_idx
  ON policies (tenant_id, created_at DESC)
  WHERE deleted_at IS NULL;

CREATE INDEX policies_tenant_slug_idx
  ON policies (tenant_id, slug)
  WHERE deleted_at IS NULL;

CREATE TRIGGER policies_set_updated_at
  BEFORE UPDATE ON policies
  FOR EACH ROW
  EXECUTE FUNCTION av_set_updated_at();

-- ---------------------------------------------------------------------------
-- policy_versions — immutable version history
-- ---------------------------------------------------------------------------
CREATE TABLE policy_versions (
  id                uuid PRIMARY KEY,
  policy_id         uuid NOT NULL REFERENCES policies (id) ON DELETE CASCADE,
  version           integer NOT NULL,
  status            text NOT NULL,
  default_action    text NOT NULL,
  content_sha256    text NOT NULL,
  compiled_blob     bytea,
  effective_from    timestamptz,
  effective_to      timestamptz,
  published_at      timestamptz,
  archived_at       timestamptz,
  created_by        uuid,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT policy_versions_version_positive CHECK (version > 0),
  CONSTRAINT policy_versions_status_chk CHECK (
    status IN ('draft', 'active', 'archived')
  ),
  CONSTRAINT policy_versions_default_action_chk CHECK (
    default_action IN ('allow', 'deny', 'require_approval', 'downgrade', 'pause')
  ),
  CONSTRAINT policy_versions_effective_range_chk CHECK (
    effective_from IS NULL
    OR effective_to IS NULL
    OR effective_from <= effective_to
  ),
  CONSTRAINT policy_versions_unique_version UNIQUE (policy_id, version)
);

CREATE INDEX policy_versions_policy_status_idx
  ON policy_versions (policy_id, status);

CREATE INDEX policy_versions_tenant_lookup_idx
  ON policy_versions (policy_id, version DESC);

CREATE INDEX policy_versions_active_idx
  ON policy_versions (policy_id)
  WHERE status = 'active';

CREATE INDEX policy_versions_created_idx
  ON policy_versions (created_at DESC);

CREATE TRIGGER policy_versions_set_updated_at
  BEFORE UPDATE ON policy_versions
  FOR EACH ROW
  EXECUTE FUNCTION av_set_updated_at();

-- ---------------------------------------------------------------------------
-- policy_rules — rules belonging to a specific policy version
-- ---------------------------------------------------------------------------
CREATE TABLE policy_rules (
  id                uuid PRIMARY KEY,
  policy_version_id uuid NOT NULL REFERENCES policy_versions (id) ON DELETE CASCADE,
  rule_key          text NOT NULL,
  priority          integer NOT NULL DEFAULT 0,
  enabled           boolean NOT NULL DEFAULT true,
  target_type       text NOT NULL,
  target_selector   jsonb NOT NULL DEFAULT '{}'::jsonb,
  conditions        jsonb NOT NULL DEFAULT '[]'::jsonb,
  action            text NOT NULL,
  action_config     jsonb NOT NULL DEFAULT '{}'::jsonb,
  reason_code       text NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT policy_rules_target_type_chk CHECK (
    target_type IN ('model', 'tool', 'write_action', 'delegation', 'budget')
  ),
  CONSTRAINT policy_rules_action_chk CHECK (
    action IN ('allow', 'deny', 'require_approval', 'downgrade', 'pause')
  ),
  CONSTRAINT policy_rules_rule_key_per_version UNIQUE (policy_version_id, rule_key)
);

CREATE INDEX policy_rules_version_priority_idx
  ON policy_rules (policy_version_id, priority DESC, id);

CREATE INDEX policy_rules_reason_idx
  ON policy_rules (reason_code);

CREATE TRIGGER policy_rules_set_updated_at
  BEFORE UPDATE ON policy_rules
  FOR EACH ROW
  EXECUTE FUNCTION av_set_updated_at();

-- ---------------------------------------------------------------------------
-- runs — agent run context (tenant_id for RLS)
-- ---------------------------------------------------------------------------
CREATE TABLE runs (
  id                      uuid PRIMARY KEY,
  tenant_id               uuid NOT NULL,
  agent_id                uuid NOT NULL,
  workspace_id            uuid,
  project_id              uuid,
  policy_version_id       uuid REFERENCES policy_versions (id) ON DELETE SET NULL,
  status                  text NOT NULL,
  mode                    text NOT NULL DEFAULT 'enforce',
  budget_usd_reserved     numeric(18, 6) NOT NULL DEFAULT 0,
  budget_usd_estimated    numeric(18, 6) NOT NULL DEFAULT 0,
  budget_usd_actual       numeric(18, 6) NOT NULL DEFAULT 0,
  started_at              timestamptz NOT NULL DEFAULT now(),
  ended_at                timestamptz,
  last_heartbeat_at       timestamptz,
  metadata                jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at              timestamptz NOT NULL DEFAULT now(),
  updated_at              timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT runs_status_chk CHECK (
    status IN ('pending', 'running', 'completed', 'failed', 'cancelled', 'blocked')
  ),
  CONSTRAINT runs_mode_chk CHECK (
    mode IN ('monitor', 'enforce', 'standalone')
  ),
  CONSTRAINT runs_budget_non_negative_chk CHECK (
    budget_usd_reserved >= 0
    AND budget_usd_estimated >= 0
    AND budget_usd_actual >= 0
  ),
  CONSTRAINT runs_time_order_chk CHECK (
    ended_at IS NULL OR ended_at >= started_at
  )
);

CREATE INDEX runs_tenant_started_idx
  ON runs (tenant_id, started_at DESC);

CREATE INDEX runs_tenant_agent_started_idx
  ON runs (tenant_id, agent_id, started_at DESC);

CREATE INDEX runs_tenant_status_idx
  ON runs (tenant_id, status, started_at DESC);

CREATE INDEX runs_policy_version_idx
  ON runs (policy_version_id)
  WHERE policy_version_id IS NOT NULL;

CREATE TRIGGER runs_set_updated_at
  BEFORE UPDATE ON runs
  FOR EACH ROW
  EXECUTE FUNCTION av_set_updated_at();

-- ---------------------------------------------------------------------------
-- run_steps — partitioned append-heavy steps (tenant_id for RLS)
-- ---------------------------------------------------------------------------
CREATE TABLE run_steps (
  id                uuid NOT NULL,
  run_id            uuid NOT NULL REFERENCES runs (id) ON DELETE CASCADE,
  tenant_id         uuid NOT NULL,
  step_index        integer NOT NULL,
  action_type       text NOT NULL,
  tool_name         text,
  cost_usd          numeric(18, 6) NOT NULL DEFAULT 0,
  outcome           text NOT NULL,
  decision          text NOT NULL,
  reason_code       text,
  span_id           uuid,
  started_at        timestamptz NOT NULL DEFAULT now(),
  ended_at          timestamptz,
  payload           jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at        timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id, started_at),
  CONSTRAINT run_steps_step_unique UNIQUE (run_id, step_index, started_at),
  CONSTRAINT run_steps_outcome_chk CHECK (
    outcome IN ('success', 'failure', 'skipped', 'unknown')
  ),
  CONSTRAINT run_steps_decision_chk CHECK (
    decision IN ('allow', 'deny', 'downgrade', 'pause', 'require_approval')
  ),
  CONSTRAINT run_steps_time_order_chk CHECK (
    ended_at IS NULL OR ended_at >= started_at
  )
) PARTITION BY RANGE (started_at);

CREATE INDEX run_steps_run_started_idx
  ON run_steps (run_id, started_at);

CREATE INDEX run_steps_tenant_started_idx
  ON run_steps (tenant_id, started_at DESC);

CREATE INDEX run_steps_decision_started_idx
  ON run_steps (decision, started_at DESC);

CREATE TABLE run_steps_y2026m04 PARTITION OF run_steps
  FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');

CREATE TABLE run_steps_y2026m05 PARTITION OF run_steps
  FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');

CREATE TABLE run_steps_default PARTITION OF run_steps DEFAULT;

COMMENT ON TABLE policies IS 'RLS-ready: enable ROW LEVEL SECURITY + tenant policies when app sets session context.';
COMMENT ON TABLE runs IS 'RLS-ready: tenant_id is the isolation key.';
