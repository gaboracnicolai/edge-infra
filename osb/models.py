"""Pydantic models for the OSB API and persistence layer."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import AnyHttpUrl, BaseModel, Field, field_validator, model_validator

import netguard
import specvalidation


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
    team: str = Field(pattern=r"^[a-z][a-z0-9-]{1,62}$")
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    protocol: Literal["HTTP", "HTTPS"] = "HTTP"
    tls_secret_name: str | None = None
    auth_policy: Literal["none", "jwt", "mtls", "jwt_or_mtls"] = "jwt"
    rate_limit: RateLimitSpec | None = None
    health_check: HealthCheckSpec | None = None
    node_selector: dict[str, str] = Field(default_factory=dict)
    webhook_url: AnyHttpUrl | None = None

    @field_validator("webhook_url")
    @classmethod
    def _webhook_url_not_internal(cls, v: AnyHttpUrl | None) -> AnyHttpUrl | None:
        """Reject an IP-literal webhook target that points at an internal host
        (SSRF, ISO 27001 A.13/A.14). Hostnames are re-checked at delivery time."""
        if v is not None:
            netguard.validate_webhook_url(str(v))
        return v

    @field_validator("host")
    @classmethod
    def _host_is_ip_or_hostname(cls, v: str) -> str:
        """Constrain host to an IP literal or RFC-1123 hostname — it is
        interpolated into Envoy/xDS cluster config (ISO 27001 A.14)."""
        return specvalidation.validate_host(v)

    @field_validator("node_selector")
    @classmethod
    def _node_selector_bounded(cls, v: dict[str, str]) -> dict[str, str]:
        """Bound node_selector size and reject control chars. Charset semantics
        stay with the xDS layer (see specvalidation.validate_node_selector)."""
        return specvalidation.validate_node_selector(v)

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
