-- R9: OSB dead-letter for provisioning messages that exhaust their JetStream
-- redelivery budget (max_deliver). The worker routes an exhausted message here
-- and acks it — so a permanently-failing message is neither retried forever nor
-- silently dropped, and stays diagnosable/replayable.
--
-- payload is the raw NATS message data (a ServiceSpec / deprovision payload) —
-- REFERENCES only (tls_secret_name / client_ca_secret_name are names), never
-- cert/key/password material, so it is safe to retain.

CREATE TABLE IF NOT EXISTS dead_letter (
    id         BIGSERIAL PRIMARY KEY,
    msg_id     TEXT,
    subject    TEXT NOT NULL,
    operation  TEXT NOT NULL,
    payload    TEXT NOT NULL,
    error      TEXT NOT NULL,
    delivered  INT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Lookup index for diagnosis/replay by message id. The worker only writes here
-- on the FINAL delivery and then acks, so re-delivery can't produce duplicates in
-- practice — no uniqueness needed.
CREATE INDEX IF NOT EXISTS idx_dead_letter_msg_id ON dead_letter (msg_id);
