-- B28.228: edge-egress's decision log. One row per request an edge-egress
-- Envoy decided (sent on, refused, or refused for the agent's rate limit),
-- appended by the control plane as the Envoys report them.
--
-- line is the record exactly as it was hashed and as it is exported: one line
-- of JSON that names the hash of the line before it (prev). hash is the hex
-- sha256 of line. seq is the record's place in the chain, from 1.
--
-- Expand-only: a new table.

CREATE TABLE IF NOT EXISTS edge_decisions (
    seq         BIGINT PRIMARY KEY CHECK (seq > 0),
    line        TEXT NOT NULL,
    hash        CHAR(64) NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
