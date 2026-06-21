-- Issuer user store. This lives in its OWN database (ISSUER_DATABASE_URL),
-- separate from the xDS control-plane Postgres, so a compromise of one store
-- cannot read the other's data (credential hashes vs. routing config).

CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,            -- argon2id PHC string
    display_name  TEXT NOT NULL DEFAULT '',
    disabled_at   TIMESTAMPTZ,             -- non-null => fail closed, no tokens
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The source of the JWT `teams` claim. Track has no member<->team mapping,
-- so team membership is owned here until/unless that converges.
CREATE TABLE IF NOT EXISTS user_teams (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    team    TEXT NOT NULL,
    PRIMARY KEY (user_id, team)
);

CREATE INDEX IF NOT EXISTS idx_user_teams_user ON user_teams(user_id);
