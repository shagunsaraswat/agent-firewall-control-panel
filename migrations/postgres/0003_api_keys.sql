-- API keys for SDK / automation authentication (hashed at rest).

CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    key_hash BYTEA NOT NULL,
    key_prefix VARCHAR(8) NOT NULL,
    permissions TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_by TEXT NOT NULL DEFAULT 'system',
    CONSTRAINT api_keys_key_hash_unique UNIQUE (key_hash)
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys (key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys (tenant_id);
