CREATE TABLE IF NOT EXISTS secrets (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    cert_pem    TEXT NOT NULL,
    key_pem     TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS gateways (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    port        INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol    TEXT NOT NULL CHECK (protocol IN ('HTTP', 'HTTPS')),
    tls_secret  TEXT REFERENCES secrets(name),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS clusters (
    id                 TEXT PRIMARY KEY,
    name               TEXT NOT NULL UNIQUE,
    connect_timeout_ms BIGINT NOT NULL DEFAULT 5000,
    lb_policy          TEXT NOT NULL DEFAULT 'ROUND_ROBIN',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS endpoints (
    id          TEXT PRIMARY KEY,
    cluster_id  TEXT NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    address     TEXT NOT NULL,
    port        INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    weight      INTEGER NOT NULL DEFAULT 1 CHECK (weight > 0),
    UNIQUE (cluster_id, address, port)
);

CREATE TABLE IF NOT EXISTS routes (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    gateway_id    TEXT NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
    hosts         TEXT[] NOT NULL DEFAULT ARRAY['*']::TEXT[],
    path_prefix   TEXT NOT NULL DEFAULT '/',
    cluster_name  TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_endpoints_cluster_id ON endpoints(cluster_id);
CREATE INDEX IF NOT EXISTS idx_routes_gateway_id ON routes(gateway_id);
