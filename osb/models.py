"""Pydantic models for the OSB API and persistence layer."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import AnyHttpUrl, BaseModel, Field, model_validator


class RateLimitSpec(BaseModel):
    """Per-service rate limit declaration."""

    requests_per_unit: int = Field(ge=1)
    unit: Literal["SECOND", "MINUTE", "HOUR"]


class HealthCheckSpec(BaseModel):
    """Active health-check declaration."""

    path: str = "/healthz"
    interval_seconds: int = Field(default=5, ge=1)


class ServiceSpec(BaseModel):
    """Tenant-supplied desired state for a service registration."""

    name: str = Field(pattern=r"^[a-z][a-z0-9-]{1,62}$")
    team: str
    host: str
    port: int = Field(ge=1, le=65535)
    protocol: Literal["HTTP", "HTTPS"] = "HTTP"
    tls_secret_name: str | None = None
    auth_policy: Literal["none", "jwt", "mtls", "jwt_or_mtls"] = "jwt"
    rate_limit: RateLimitSpec | None = None
    health_check: HealthCheckSpec | None = None
    node_selector: dict[str, str] = Field(default_factory=dict)
    webhook_url: AnyHttpUrl | None = None

    @model_validator(mode="after")
    def _https_requires_tls_secret(self) -> ServiceSpec:
        if self.protocol == "HTTPS" and self.tls_secret_name is None:
            raise ValueError("tls_secret_name is required when protocol is HTTPS")
        return self


class ProvisionResponse(BaseModel):
    """Returned synchronously when a CREATE or DELETE is accepted."""

    request_id: UUID
    status: Literal["PENDING", "COMPLETED", "FAILED"]
    message: str


class ProvisionRequest(BaseModel):
    """Row representation for /v1/requests/{request_id}."""

    id: UUID
    operation: str
    status: str
    payload: str
    webhook_url: str | None = None
    error: str | None = None
    completed_at: datetime | None = None
    created_at: datetime
