CREATE TABLE IF NOT EXISTS idempotency_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    operation VARCHAR(128) NOT NULL,
    idempotency_key VARCHAR(256) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'processing',
    response_status_code INTEGER,
    response_body JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, operation, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_idempotency_tenant_op_key ON idempotency_keys (tenant_id, operation, idempotency_key);
CREATE INDEX IF NOT EXISTS idx_idempotency_expires ON idempotency_keys (expires_at) WHERE status = 'processing';
