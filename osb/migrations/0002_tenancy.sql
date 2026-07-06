-- R4 Stage 2: enforced tenant isolation.
--
-- services.name becomes UNIQUE(team, name) so two teams can register the same
-- service name; the worker's upsert conflict target changes to (team, name) in
-- lockstep. Existing names are globally unique, hence trivially per-team-unique
-- — no data migration. The shared gateway (osb-shared-http) is owner-less and
-- untouched by any per-tenant scoping.
--
-- Reverse is only clean before two teams share a name: DROP the composite
-- constraint and re-ADD UNIQUE(name) fails once duplicate names exist.

-- Per-team uniqueness (was UNIQUE(name); services_name_key is the Postgres
-- auto-name for the `name TEXT ... UNIQUE` column constraint).
ALTER TABLE services DROP CONSTRAINT IF EXISTS services_name_key;
ALTER TABLE services ADD CONSTRAINT services_team_name_key UNIQUE (team, name);

-- Scope provision_requests to a tenant so GET /v1/requests/{id} cannot be read
-- cross-tenant. Nullable — rows written before Stage 2 have NULL team.
ALTER TABLE provision_requests ADD COLUMN IF NOT EXISTS team TEXT;

-- Per-tenant API keys: hashed at rest (SHA-256 hex), rotatable, multiple keys
-- per team allowed. A verified bearer resolves to exactly one team = the
-- request's tenant. This is the ONLY source of caller tenancy — the request
-- body can never set it.
CREATE TABLE IF NOT EXISTS tenant_api_keys (
    key_hash    TEXT PRIMARY KEY,
    team        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_tenant_api_keys_team ON tenant_api_keys(team);
