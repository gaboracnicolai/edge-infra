"""Broker entry points used by the FastAPI endpoints."""

from __future__ import annotations

import json
from uuid import uuid4

import structlog

import metrics
from config import Settings
from models import ProvisionResponse, ServiceSpec

log = structlog.get_logger(__name__)


async def provision(spec: ServiceSpec, pool, js, cfg: Settings) -> ProvisionResponse:
    """Persist a CREATE request and publish it to JetStream.

    The DB insert happens before the publish so the request is durable; if
    publish fails the row is removed so the caller sees a clean 5xx.
    """
    request_id = uuid4()
    payload_json = spec.model_dump_json()
    webhook_url = str(spec.webhook_url) if spec.webhook_url else None

    await pool.execute(
        """
        INSERT INTO provision_requests (id, operation, status, payload, webhook_url)
        VALUES ($1, 'CREATE', 'PENDING', $2::jsonb, $3)
        ON CONFLICT (id) DO NOTHING
        """,
        request_id,
        payload_json,
        webhook_url,
    )

    try:
        await js.publish(
            cfg.nats_subject_provision,
            payload_json.encode(),
            headers={"Nats-Msg-Id": str(request_id)},
        )
    except Exception:
        await pool.execute(
            "DELETE FROM provision_requests WHERE id = $1",
            request_id,
        )
        log.exception("nats publish failed; rolled back provision row", request_id=str(request_id))
        raise

    metrics.requests_total[("CREATE", "PENDING")] += 1
    log.info("provision queued", request_id=str(request_id), service=spec.name)

    return ProvisionResponse(
        request_id=request_id,
        status="PENDING",
        message=f"CREATE for service {spec.name!r} queued",
    )


async def deprovision(name: str, pool, js, cfg: Settings) -> ProvisionResponse:
    """Persist a DELETE request and publish it to JetStream (same pattern as provision)."""
    request_id = uuid4()
    payload = json.dumps({"name": name})

    await pool.execute(
        """
        INSERT INTO provision_requests (id, operation, status, payload, webhook_url)
        VALUES ($1, 'DELETE', 'PENDING', $2::jsonb, NULL)
        ON CONFLICT (id) DO NOTHING
        """,
        request_id,
        payload,
    )

    try:
        await js.publish(
            cfg.nats_subject_deprovision,
            payload.encode(),
            headers={"Nats-Msg-Id": str(request_id)},
        )
    except Exception:
        await pool.execute(
            "DELETE FROM provision_requests WHERE id = $1",
            request_id,
        )
        log.exception(
            "nats publish failed; rolled back deprovision row",
            request_id=str(request_id),
        )
        raise

    metrics.requests_total[("DELETE", "PENDING")] += 1
    log.info("deprovision queued", request_id=str(request_id), service=name)

    return ProvisionResponse(
        request_id=request_id,
        status="PENDING",
        message=f"DELETE for service {name!r} queued",
    )
