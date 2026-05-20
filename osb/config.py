"""Process configuration sourced from environment variables."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All values are populated from environment variables (or .env for local dev)."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = "postgresql://localhost/edge_osb"
    nats_url: str = "nats://localhost:4222"
    nats_stream: str = "EDGE"
    nats_subject_provision: str = "edge.provision.create"
    nats_subject_deprovision: str = "edge.provision.delete"
    nats_consumer_durable: str = "osb-workers"
    webhook_timeout_s: float = 5.0
    webhook_max_retries: int = 5
    webhook_retry_base_s: float = 2.0
    listen_addr: str = "0.0.0.0"  # noqa: S104 — broker binds in-cluster
    listen_port: int = 8080
    log_level: str = "INFO"
