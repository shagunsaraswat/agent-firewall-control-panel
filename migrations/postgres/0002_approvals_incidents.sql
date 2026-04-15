-- Agent FirewallKit: approvals, incidents, learner candidates, webhooks, audit.
-- Aligned with final_prd/09-data-models.md §1.2.

CREATE OR REPLACE FUNCTION av_audit_immutable()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- approvals — witness hash, status FSM, expiry
-- ---------------------------------------------------------------------------
CREATE TABLE approvals (
  id                uuid PRIMARY KEY,
  tenant_id         uuid NOT NULL,
  run_id            uuid NOT NULL REFERENCES runs (id) ON DELETE CASCADE,
  status            text NOT NULL DEFAULT 'pending',
  witness_hash      bytea NOT NULL,
  resource_fingerprint text,
  requested_action  jsonb NOT NULL DEFAULT '{}'::jsonb,
  approver_id       uuid,
  resolution_note   text,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  expires_at        timestamptz NOT NULL,
  resolved_at       timestamptz,
  CONSTRAINT approvals_status_chk CHECK (
    status IN ('pending', 'approved', 'denied', 'expired', 'cancelled')
  ),
  CONSTRAINT approvals_expiry_chk CHECK (expires_at > created_at),
  CONSTRAINT approvals_resolved_chk CHECK (
    (status IN ('approved', 'denied', 'expired', 'cancelled')) = (resolved_at IS NOT NULL)
  )
);

CREATE INDEX approvals_tenant_status_expires_idx
  ON approvals (tenant_id, status, expires_at);

CREATE INDEX approvals_run_idx
  ON approvals (run_id, created_at DESC);

CREATE INDEX approvals_pending_expires_idx
  ON approvals (expires_at)
  WHERE status = 'pending';

CREATE TRIGGER approvals_set_updated_at
  BEFORE UPDATE ON approvals
  FOR EACH ROW
  EXECUTE FUNCTION av_set_updated_at();

-- ---------------------------------------------------------------------------
-- incidents — severity, status; remediation_steps stored in detail JSONB
-- ---------------------------------------------------------------------------
CREATE TABLE incidents (
  id                uuid PRIMARY KEY,
  tenant_id         uuid NOT NULL,
  run_id            uuid REFERENCES runs (id) ON DELETE SET NULL,
  approval_id       uuid REFERENCES approvals (id) ON DELETE SET NULL,
  severity          text NOT NULL,
  reason_code       text NOT NULL,
  status            text NOT NULL DEFAULT 'open',
  title             text NOT NULL,
  detail            jsonb NOT NULL DEFAULT '{}'::jsonb,
  occurred_at       timestamptz NOT NULL DEFAULT now(),
  resolved_at       timestamptz,
  resolved_by       uuid,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT incidents_severity_chk CHECK (
    severity IN ('info', 'low', 'medium', 'high', 'critical')
  ),
  CONSTRAINT incidents_status_chk CHECK (
    status IN ('open', 'acknowledged', 'resolved', 'dismissed')
  ),
  CONSTRAINT incidents_resolved_order_chk CHECK (
    resolved_at IS NULL OR resolved_at >= occurred_at
  )
);

CREATE INDEX incidents_tenant_occurred_idx
  ON incidents (tenant_id, occurred_at DESC);

CREATE INDEX incidents_tenant_status_idx
  ON incidents (tenant_id, status, occurred_at DESC);

CREATE INDEX incidents_run_idx
  ON incidents (run_id, occurred_at DESC);

CREATE INDEX incidents_reason_idx
  ON incidents (reason_code, occurred_at DESC);

CREATE TRIGGER incidents_set_updated_at
  BEFORE UPDATE ON incidents
  FOR EACH ROW
  EXECUTE FUNCTION av_set_updated_at();

COMMENT ON COLUMN incidents.detail IS 'JSON payload: context, remediation_steps array, policy_id, scope, owner, etc.';

-- ---------------------------------------------------------------------------
-- policy_candidates — learner output (proposed / approved / rejected / superseded)
-- ---------------------------------------------------------------------------
CREATE TABLE policy_candidates (
  id                uuid PRIMARY KEY,
  tenant_id         uuid NOT NULL,
  source_run_id     uuid REFERENCES runs (id) ON DELETE SET NULL,
  status            text NOT NULL DEFAULT 'proposed',
  summary           text,
  proposed_rules    jsonb NOT NULL DEFAULT '[]'::jsonb,
  metrics           jsonb NOT NULL DEFAULT '{}'::jsonb,
  review_note       text,
  reviewed_by       uuid,
  reviewed_at       timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT policy_candidates_status_chk CHECK (
    status IN ('proposed', 'approved', 'rejected', 'superseded')
  )
);

CREATE INDEX policy_candidates_tenant_status_idx
  ON policy_candidates (tenant_id, status, created_at DESC);

CREATE INDEX policy_candidates_source_run_idx
  ON policy_candidates (source_run_id)
  WHERE source_run_id IS NOT NULL;

CREATE TRIGGER policy_candidates_set_updated_at
  BEFORE UPDATE ON policy_candidates
  FOR EACH ROW
  EXECUTE FUNCTION av_set_updated_at();

-- ---------------------------------------------------------------------------
-- webhook_subscriptions
-- ---------------------------------------------------------------------------
CREATE TABLE webhook_subscriptions (
  id                uuid PRIMARY KEY,
  tenant_id         uuid NOT NULL,
  url               text NOT NULL,
  description       text,
  events            text[] NOT NULL,
  secret_hmac_sha256 bytea NOT NULL,
  status            text NOT NULL DEFAULT 'active',
  failure_count     integer NOT NULL DEFAULT 0,
  last_delivery_at  timestamptz,
  last_error        text,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT webhook_subscriptions_status_chk CHECK (
    status IN ('active', 'paused', 'disabled')
  ),
  CONSTRAINT webhook_subscriptions_events_not_empty_chk CHECK (
    cardinality(events) >= 1
  ),
  CONSTRAINT webhook_subscriptions_url_https_chk CHECK (
    url ~* '^https://'
  ),
  CONSTRAINT webhook_subscriptions_failure_count_chk CHECK (failure_count >= 0)
);

CREATE INDEX webhook_subscriptions_tenant_status_idx
  ON webhook_subscriptions (tenant_id, status);

CREATE INDEX webhook_subscriptions_events_gin_idx
  ON webhook_subscriptions USING gin (events);

CREATE TRIGGER webhook_subscriptions_set_updated_at
  BEFORE UPDATE ON webhook_subscriptions
  FOR EACH ROW
  EXECUTE FUNCTION av_set_updated_at();

-- ---------------------------------------------------------------------------
-- audit_log — append-only, partitioned
-- ---------------------------------------------------------------------------
CREATE TABLE audit_log (
  id                uuid NOT NULL,
  tenant_id         uuid NOT NULL,
  actor_id          uuid,
  actor_type        text NOT NULL DEFAULT 'user',
  action            text NOT NULL,
  resource_type     text NOT NULL,
  resource_id       uuid,
  request_id        uuid,
  outcome           text NOT NULL,
  metadata          jsonb NOT NULL DEFAULT '{}'::jsonb,
  ip_inet           inet,
  user_agent        text,
  recorded_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id, recorded_at),
  CONSTRAINT audit_log_actor_type_chk CHECK (
    actor_type IN ('user', 'service', 'system', 'api_key')
  ),
  CONSTRAINT audit_log_outcome_chk CHECK (
    outcome IN ('success', 'failure', 'denied', 'unknown')
  )
) PARTITION BY RANGE (recorded_at);

CREATE INDEX audit_log_tenant_time_idx
  ON audit_log (tenant_id, recorded_at DESC);

CREATE INDEX audit_log_resource_idx
  ON audit_log (resource_type, resource_id, recorded_at DESC);

CREATE INDEX audit_log_action_time_idx
  ON audit_log (action, recorded_at DESC);

CREATE TABLE audit_log_y2026m04 PARTITION OF audit_log
  FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');

CREATE TABLE audit_log_y2026m05 PARTITION OF audit_log
  FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');

CREATE TABLE audit_log_default PARTITION OF audit_log DEFAULT;

CREATE TRIGGER audit_log_immutable_update
  BEFORE UPDATE ON audit_log
  FOR EACH ROW
  EXECUTE FUNCTION av_audit_immutable();

CREATE TRIGGER audit_log_immutable_delete
  BEFORE DELETE ON audit_log
  FOR EACH ROW
  EXECUTE FUNCTION av_audit_immutable();
