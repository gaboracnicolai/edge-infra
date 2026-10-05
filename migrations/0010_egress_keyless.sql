-- B28.224: keyless agents. A keyless destination takes no credential from the
-- agent. On edge-egress its plain-HTTP requests go through ext_authz in the
-- auth-service's agent mode: the agent proves who it is with its workload
-- token in Proxy-Authorization, every credential it sent is removed, and a
-- signed transit assertion (x-gateway-auth) is added for the upstream (Lens)
-- to accept. CONNECT to a keyless host is refused with 403, because a tunnel
-- would carry the agent's own credentials past the gateway unseen.
--
-- Expand-only: existing rows stay as they were (keyless = false).

ALTER TABLE egress_destinations
    ADD COLUMN IF NOT EXISTS keyless BOOLEAN NOT NULL DEFAULT false;
