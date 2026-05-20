-- OSB self-service broker schema.
--
-- The Go control-plane migrations (0001_init.sql, 0002_controller_fields.sql)
-- do not create provision_requests or services; the broker owns them. The
-- ALTERs at the bottom are kept as forward-compatible upgrade safety in case
-- an earlier deployment created provision_requests without them.

CREATE TABLE IF NOT EXISTS provision_requests (
    id            UUID PRIMARY KEY,
    operation     TEXT NOT NULL CHECK (operation IN ('CREATE', 'DELETE')),
    status        TEXT NOT NULL CHECK (status IN ('PENDING', 'COMPLETED', 'FAILED')),
    payload       JSONB NOT NULL,
    webhook_url   TEXT,
    error         TEXT,
    completed_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_provision_requests_status
    ON provision_requests(status);

CREATE TABLE IF NOT EXISTS services (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name             TEXT NOT NULL UNIQUE,
    team             TEXT NOT NULL,
    host             TEXT NOT NULL,
    port             INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol         TEXT NOT NULL CHECK (protocol IN ('HTTP', 'HTTPS')),
    tls_secret_name  TEXT,
    auth_policy      TEXT NOT NULL DEFAULT 'jwt',
    rate_limit       JSONB,
    health_check     JSONB,
    node_selector    JSONB DEFAULT '{}',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at       TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_services_active
    ON services(deleted_at) WHERE deleted_at IS NULL;

-- Forward-compatible upgrade for any deployment where provision_requests
-- pre-existed without these columns. No-op on a fresh install.
ALTER TABLE provision_requests
    ADD COLUMN IF NOT EXISTS webhook_url  TEXT,
    ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS error        TEXT;
