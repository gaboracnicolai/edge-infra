-- R4 Stage 3a-i: per-service rate_limit + health_check rendered onto the derived
-- route / cluster rows.
--
-- Additive + NULLABLE by design: existing controller-provisioned routes/clusters
-- (NULL policy) render exactly as before — no rate limit, no health check — so
-- this is backward-compatible and reversible (DROP COLUMN) while unused.

ALTER TABLE routes   ADD COLUMN IF NOT EXISTS rate_limit_per_unit INT;   -- NULL = no limit
ALTER TABLE routes   ADD COLUMN IF NOT EXISTS rate_limit_unit     TEXT;  -- SECOND | MINUTE | HOUR

ALTER TABLE clusters ADD COLUMN IF NOT EXISTS health_check_path       TEXT; -- NULL = no health check
ALTER TABLE clusters ADD COLUMN IF NOT EXISTS health_check_interval_s INT;
