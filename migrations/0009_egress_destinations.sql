-- B28.222: the egress gateway's allow-list. One row is one outside host an agent
-- may reach through edge-egress, and nothing else is reachable through it.
--
-- Each row renders, on the edge-egress Envoys only:
--   * a DNS cluster to host:port with upstream TLS — SNI = host, the server's
--     certificate verified against ca_secret_name, or the proxy's system trust
--     store when it is NULL — serving plain-HTTP requests for the host;
--   * a raw-TCP DNS cluster to the same host:port, serving CONNECT host:port
--     tunnels, where the agent's own TLS runs end to end.
-- A host with no row gets 403 from edge-egress, CONNECT included.
--
-- ca_secret_name is a REFERENCE to a validation_context row in secrets, served
-- over SDS, deliberately with no foreign key (the same decoupling as
-- routes.client_ca_secret_name): a name that does not resolve leaves the
-- upstream handshake unverifiable, so it fails closed.

CREATE TABLE IF NOT EXISTS egress_destinations (
    id                 TEXT PRIMARY KEY,
    -- Names the destination's clusters (egress_<name>, egress_<name>_tunnel).
    name               TEXT NOT NULL UNIQUE
                       CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    -- A DNS name, lower case, no port and no wildcard.
    host               TEXT NOT NULL UNIQUE
                       CHECK (host ~ '^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$'),
    port               INTEGER NOT NULL DEFAULT 443 CHECK (port BETWEEN 1 AND 65535),
    ca_secret_name     TEXT CHECK (ca_secret_name IS NULL OR btrim(ca_secret_name) <> ''),
    connect_timeout_ms BIGINT NOT NULL DEFAULT 5000 CHECK (connect_timeout_ms > 0),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
