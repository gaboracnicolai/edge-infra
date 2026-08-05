-- 0008: an mtls route MUST name a client CA — enforced at rest.
--
-- THE HOLE THIS CLOSES. auth_policy='mtls' means "the client cert IS the auth",
-- so the renderer sets ExtAuthzPerRoute{Disabled} for that route: no JWT check,
-- no auth-service call. The matching cert requirement is emitted ONLY when a
-- client-CA name is present (lds.go: `if clientCAName != ""` gates both the
-- validation_context and require_client_certificate). A row with
-- auth_policy='mtls' and a NULL/empty client_ca_secret_name therefore renders a
-- listener that authenticates nobody by EITHER mechanism — an open route.
--
-- ⚠ 0007's COMMENT ASSERTED THE OPPOSITE and has been corrected in place. It
-- said a missing CA "renders an unresolved SDS ref, so that SNI's mTLS handshake
-- fails closed (never a bypass)". That is true when the NAME IS PRESENT and does
-- not resolve to a secret. It is false when the name is ABSENT, because then
-- there is no SDS reference at all to be unresolved — and NULLABLE is precisely
-- what creates that second case.
--
-- NOT REACHABLE TODAY, verified rather than assumed: OSB rejects None, "" and
-- whitespace for mtls, and internal/store/postgres.go never writes auth_policy
-- or client_ca_secret_name at all (its rows take the 'jwt' default). There is no
-- third writer. But a latent hole guarded only by "no current writer does that"
-- is one new writer away from live, so it is made unrepresentable here and
-- refused in the renderer (builders.AnyMTLSRouteMissingClientCA) — belt and
-- braces, because the renderer is the last line and must hold for rows that
-- arrive by paths this constraint never saw (a restored dump, a pre-constraint
-- row, a future writer).
--
-- ⚠ THIS MIGRATION FAILING IS A FINDING, NOT AN INCONVENIENCE. Postgres validates
-- the CHECK against existing rows, so if it errors, a route matching the open
-- shape already exists in that database. Do not weaken the constraint to get past
-- it — inspect the row:
--     SELECT id, name, auth_policy, client_ca_secret_name FROM routes
--      WHERE auth_policy = 'mtls'
--        AND (client_ca_secret_name IS NULL OR btrim(client_ca_secret_name) = '');
--
-- jwt_or_mtls is deliberately NOT constrained: the renderer keeps ext_authz
-- ENABLED for it, so a cert-less caller falls through to the JWT path. Requiring
-- a CA there would reject a configuration that is safe today. (OSB's API does
-- require one for both — a stricter API over a permissive schema is fine; the
-- reverse is not.)

ALTER TABLE routes
    ADD CONSTRAINT routes_mtls_requires_client_ca
    CHECK (
        auth_policy <> 'mtls'
        OR (client_ca_secret_name IS NOT NULL AND btrim(client_ca_secret_name) <> '')
    );
