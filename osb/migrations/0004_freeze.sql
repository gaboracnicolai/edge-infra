-- B28.197: a provisioning freeze that holds.
--
-- During an ext_authz rollback OSB re-provisioning restores auth_policy from the
-- service spec, undoing the rollback one service at a time. Scaling the worker to
-- 0 does not stop it: ArgoCD selfHeal puts the replicas back within minutes. This
-- one-row flag is the lever instead. While `frozen` is true the API answers 503
-- to every POST/DELETE and the worker holds queued specs unapplied (without
-- spending their redelivery budget); setting it false applies them in order.
--
--   UPDATE osb_freeze SET frozen = true,  reason = '<incident>', updated_at = now();
--   UPDATE osb_freeze SET frozen = false, reason = NULL,         updated_at = now();
--
-- The worker reads the row FOR SHARE inside each apply transaction, so once the
-- freezing UPDATE commits no further spec can commit.

CREATE TABLE IF NOT EXISTS osb_freeze (
    id          BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    frozen      BOOLEAN NOT NULL DEFAULT FALSE,
    reason      TEXT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO osb_freeze (id) VALUES (TRUE) ON CONFLICT (id) DO NOTHING;
