"""FastAPI broker entrypoint: validates ServiceSpec, queues work via JetStream."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated
from uuid import UUID

import nats
import structlog
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from nats.js.api import RetentionPolicy, StorageType, StreamConfig

import broker
import metrics
from config import Settings
from db import create_pool
from models import ProvisionRequest, ProvisionResponse, ServiceSpec
from security import (
    RequestIDMiddleware,
    SecurityHeadersMiddleware,
    admin_key_ok,
    bearer_token,
    secret_matches,
)
from tls import build_nats_tls

log = structlog.get_logger(__name__)
cfg = Settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Open the DB pool and NATS JetStream connection for the app's lifetime."""
    pool = await create_pool(cfg.database_url, ssl_mode=cfg.db_ssl_mode, ca_path=cfg.db_tls_ca)
    nats_tls = build_nats_tls(cfg.nats_tls_ca, cfg.nats_tls_cert, cfg.nats_tls_key)
    nc = await nats.connect(cfg.nats_url, tls=nats_tls)
    js = nc.jetstream()
    await js.add_stream(
        StreamConfig(
            name=cfg.nats_stream,
            subjects=["edge.provision.*"],
            retention=RetentionPolicy.WORK_QUEUE,
            storage=StorageType.FILE,
            duplicate_window=60,
        )
    )
    app.state.pool = pool
    app.state.js = js
    app.state.nc = nc
    if not cfg.api_key:
        log.warning(
            "provisioning API is unauthenticated (API_KEY unset) — "
            "intended for local dev only; set API_KEY in production"
        )
    log.info("osb broker ready", listen_port=cfg.listen_port)
    try:
        yield
    finally:
        await nc.drain()
        await pool.close()


app = FastAPI(title="edge-osb", version="0.1.0", lifespan=lifespan)

# Edge-of-stack middleware: stamp a request ID first (so it's bound for every
# downstream log line), then defensive headers on the way out. Starlette runs
# middleware in reverse-add order, so add headers last to wrap outermost.
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIDMiddleware)


async def require_api_key(
    authorization: Annotated[str | None, Header()] = None,
) -> None:
    """Gate the provisioning API on the shared API key (ISO 27001 A.9 — access control).

    No-op when ``API_KEY`` is unset (open mode for local dev). When set, callers
    must send ``Authorization: Bearer <key>``: 401 when the header is absent or
    not a Bearer scheme, 403 when present but wrong.

    NOTE: a shared bearer key is the lightest credential that fits the existing
    secret plumbing; whether the real provisioning callers want this, per-tenant
    keys, or mTLS (like auth-service) is Nicolai's call — this is reversible.
    """
    if not cfg.api_key:
        return
    token = bearer_token(authorization)
    if token is None:
        raise HTTPException(status_code=401, detail="API key required")
    if not secret_matches(token, cfg.api_key):
        raise HTTPException(status_code=403, detail="invalid API key")


async def require_admin(
    x_admin_key: Annotated[str | None, Header()] = None,
) -> None:
    """Gate a route on the shared admin key (ISO 27001 A.9 — access control).

    No-op when ``ADMIN_API_KEY`` is unset (open mode for local dev / an
    unconfigured scraper). When set, callers must send a matching ``X-Admin-Key``
    header: 401 when absent, 403 when present but wrong — a clear signal to a
    Prometheus scraper that is missing its credential.
    """
    if not cfg.admin_api_key:
        return
    if x_admin_key is None:
        raise HTTPException(status_code=401, detail="admin credentials required")
    if not admin_key_ok(x_admin_key, cfg.admin_api_key):
        raise HTTPException(status_code=403, detail="invalid admin credentials")


@app.post(
    "/v1/services",
    status_code=202,
    response_model=ProvisionResponse,
    dependencies=[Depends(require_api_key)],
)
async def create_service(spec: ServiceSpec, request: Request) -> ProvisionResponse:
    """Enqueue a CREATE request for an edge service."""
    try:
        return await broker.provision(spec, request.app.state.pool, request.app.state.js, cfg)
    except Exception as exc:  # noqa: BLE001 — every broker failure becomes a 500
        log.exception("provision failed", error=str(exc))
        raise HTTPException(status_code=500, detail="failed to queue provision") from exc


@app.delete(
    "/v1/services/{name}",
    status_code=202,
    response_model=ProvisionResponse,
    dependencies=[Depends(require_api_key)],
)
async def delete_service(name: str, request: Request) -> ProvisionResponse:
    """Enqueue a DELETE request for an edge service."""
    try:
        return await broker.deprovision(name, request.app.state.pool, request.app.state.js, cfg)
    except Exception as exc:  # noqa: BLE001
        log.exception("deprovision failed", error=str(exc))
        raise HTTPException(status_code=500, detail="failed to queue deprovision") from exc


@app.get(
    "/v1/requests/{request_id}",
    response_model=ProvisionRequest,
    dependencies=[Depends(require_api_key)],
)
async def get_request(request_id: UUID, request: Request) -> ProvisionRequest:
    """Return the current state of a provisioning request."""
    row = await request.app.state.pool.fetchrow(
        """
        SELECT id, operation, status, payload::text AS payload, webhook_url,
               error, completed_at, created_at
        FROM provision_requests
        WHERE id = $1
        """,
        request_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="request not found")
    return ProvisionRequest(**dict(row))


@app.get("/healthz")
async def healthz() -> dict[str, bool]:
    """Liveness endpoint."""
    return {"ok": True}


@app.get("/metrics", response_class=Response, dependencies=[Depends(require_admin)])
async def get_metrics() -> Response:
    """Prometheus text-format counters for this broker process (admin-gated)."""
    return Response(content=metrics.render(), media_type="text/plain; version=0.0.4")
