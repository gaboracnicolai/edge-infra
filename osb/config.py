"""Process configuration sourced from environment variables."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All values are populated from environment variables (or .env for local dev)."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = "postgresql://localhost/edge_osb"
    # Postgres TLS (ISO 27001 A.13). Mirrors Lens LENS_DB_SSL_MODE: defaults to
    # `require` (encrypted, no cert verification). Production sets `verify-full`
    # plus DB_TLS_CA to verify the server against the internal cert-manager CA.
    db_ssl_mode: str = "require"
    db_tls_ca: str | None = None  # CA cert path; required for verify-ca / verify-full

    nats_url: str = "nats://localhost:4222"
    nats_stream: str = "EDGE"
    nats_subject_provision: str = "edge.provision.create"
    nats_subject_deprovision: str = "edge.provision.delete"
    nats_consumer_durable: str = "osb-workers"
    # NATS TLS (ISO 27001 A.13). When NATS_TLS_CA is set the client verifies the
    # server and the connection refuses to fall back to plaintext. NATS_TLS_CERT
    # + NATS_TLS_KEY additionally enable mutual TLS.
    nats_tls_ca: str | None = None
    nats_tls_cert: str | None = None
    nats_tls_key: str | None = None

    admin_api_key: str | None = None  # gates /metrics; unset = open (local dev)
    # Bearer key for the provisioning API (POST/DELETE /v1/services, GET
    # /v1/requests). Unset = open (local dev); production sets API_KEY via the
    # config secret so callers must send `Authorization: Bearer <key>` (A.9).
    api_key: str | None = None
    webhook_timeout_s: float = 5.0
    webhook_max_retries: int = 5
    webhook_retry_base_s: float = 2.0
    # Fraction of each backoff delay added as random jitter (0 disables it).
    # Spreads retries so many workers don't hammer a recovering endpoint in lockstep.
    webhook_retry_jitter: float = 0.25

    # Retention sweep for provision_requests — the broker owns this table, and
    # without a sweep it grows unbounded (ISO 27001 A.12). The worker periodically
    # deletes terminal (COMPLETED/FAILED) rows older than the window. Set
    # PROVISION_RETENTION_DAYS=0 to disable.
    provision_retention_days: int = 30
    provision_sweep_interval_s: float = 3600.0

    listen_addr: str = "0.0.0.0"  # noqa: S104 — broker binds in-cluster
    listen_port: int = 8080
    log_level: str = "INFO"
