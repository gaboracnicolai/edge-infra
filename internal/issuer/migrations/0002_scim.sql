-- SCIM provisioning + OIDC sign-in (B27.33). A user the customer's IdP
-- provisions over SCIM has no password here — it signs in through OIDC only.
-- password_hash stays NOT NULL and holds '' for such a user, which
-- VerifyPassword can never match, so password login stays closed to it.

-- The IdP's own id for the user (SCIM externalId), echoed back on every read
-- so the IdP can match its record to ours.
ALTER TABLE users ADD COLUMN IF NOT EXISTS external_id TEXT;

-- OIDC sign-in and SCIM look users up by email case-insensitively. Not UNIQUE:
-- an existing install may already hold two emails differing only in case, and
-- a failed migration would block the deploy.
CREATE INDEX IF NOT EXISTS idx_users_email_lower ON users (lower(email));
