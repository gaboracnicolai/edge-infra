-- R4 Stage 3b-mtls (Slice 2): the derived route carries the client-CA secret
-- NAME for a per-service downstream-mTLS service (auth_policy=mtls). At the TLS
-- handshake the client cert is verified against this CA (a Slice-1
-- validation_context secret served as trusted_ca via SDS).
--
-- REFERENCE ONLY (SDS resolves the trusted_ca from the secrets table); OSB never
-- writes CA material. NULLABLE, deliberately NO foreign key — same decoupling as
-- tls_secret_name (3b-i): a missing CA renders an unresolved SDS ref, so that
-- SNI's mTLS handshake fails closed (never a bypass, never affects other SNIs).

ALTER TABLE routes ADD COLUMN client_ca_secret_name TEXT;
