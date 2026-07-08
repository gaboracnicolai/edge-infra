-- R4 Stage 3b-mtls (Slice 1): the secrets table learns a `kind` so the custodian
-- can hold cert-only client-CA trust bundles (validation_context) alongside the
-- server cert+key pairs it already stores (tls_certificate).
--
-- Additive + backward-compatible: existing rows default to 'tls_certificate';
-- key_pem becomes NULLABLE so a CA bundle (no private key) can be stored. SDS
-- serves a 'validation_context' row as a trusted_ca, a 'tls_certificate' row as
-- a cert+key — never confused.

ALTER TABLE secrets ADD COLUMN kind TEXT NOT NULL DEFAULT 'tls_certificate';
ALTER TABLE secrets ALTER COLUMN key_pem DROP NOT NULL;
