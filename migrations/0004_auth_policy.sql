-- R4 Stage 3a-ii: per-service auth_policy rendered onto the derived route.
--
-- NOT NULL DEFAULT 'jwt': a constant default is a metadata-only change (fast, no
-- table rewrite) and backfills existing controller-provisioned routes to 'jwt'
-- (authenticated), preserving today's behavior under ext_authz. The SAFE DEFAULT
-- lives here — a route can only become unauthenticated via an EXPLICIT 'none',
-- never via a missing/empty value.

ALTER TABLE routes ADD COLUMN auth_policy TEXT NOT NULL DEFAULT 'jwt';
