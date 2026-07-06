-- R4 Stage 3b-i: per-SNI HTTPS. The derived route carries the service's TLS
-- secret NAME — the SNI cert presented on the shared HTTPS listener.
--
-- REFERENCE ONLY (SDS resolves the material from the secrets table); OSB never
-- writes cert/key material. NULLABLE and deliberately NO foreign key: service
-- creation is decoupled from cert provisioning (sub-stage 2). A route whose
-- tls_secret_name has no `secrets` row renders an unresolved SDS ref → that SNI's
-- TLS handshake fails closed (never a bypass, never affects other SNIs).

ALTER TABLE routes ADD COLUMN tls_secret_name TEXT;
