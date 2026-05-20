-- Phase 2: controller-driven mutations and soft delete.

ALTER TABLE gateways ADD COLUMN IF NOT EXISTS deleted_at    TIMESTAMPTZ;
ALTER TABLE gateways ADD COLUMN IF NOT EXISTS node_selector JSONB DEFAULT '{}';

-- routes.deleted_at is required for the partial index below; the original
-- spec omitted the ALTER, included here so the migration is self-consistent.
ALTER TABLE routes ADD COLUMN IF NOT EXISTS deleted_at      TIMESTAMPTZ;
ALTER TABLE routes ADD COLUMN IF NOT EXISTS timeout_seconds INT DEFAULT 30;

CREATE INDEX IF NOT EXISTS idx_gateways_active
    ON gateways(deleted_at) WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_routes_active
    ON routes(deleted_at) WHERE deleted_at IS NULL;
