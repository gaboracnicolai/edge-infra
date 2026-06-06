"""FastAPI broker entrypoint: validates ServiceSpec, queues work via JetStream."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from uuid import UUID

import nats
import structlog
from fastapi import FastAPI, HTTPException, Request, Response
from nats.js.api import RetentionPolicy, StorageType, StreamConfig

import broker
import metrics
from config import Settings
from db import create_pool
from models import ProvisionRequest, ProvisionResponse, ServiceSpec
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
    log.info("osb broker ready", listen_port=cfg.listen_port)
    try:
        yield
    finally:
        await nc.drain()
        await pool.close()


app = FastAPI(title="edge-osb", version="0.1.0", lifespan=lifespan)


@app.post("/v1/services", status_code=202, response_model=ProvisionResponse)
async def create_service(spec: ServiceSpec, request: Request) -> ProvisionResponse:
    """Enqueue a CREATE request for an edge service."""
    try:
        return await broker.provision(spec, request.app.state.pool, request.app.state.js, cfg)
    except Exception as exc:  # noqa: BLE001 — every broker failure becomes a 500
        log.exception("provision failed", error=str(exc))
        raise HTTPException(status_code=500, detail="failed to queue provision") from exc


@app.delete("/v1/services/{name}", status_code=202, response_model=ProvisionResponse)
async def delete_service(name: str, request: Request) -> ProvisionResponse:
    """Enqueue a DELETE request for an edge service."""
    try:
        return await broker.deprovision(name, request.app.state.pool, request.app.state.js, cfg)
    except Exception as exc:  # noqa: BLE001
        log.exception("deprovision failed", error=str(exc))
        raise HTTPException(status_code=500, detail="failed to queue deprovision") from exc


@app.get("/v1/requests/{request_id}", response_model=ProvisionRequest)
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


@app.get("/metrics", response_class=Response)
async def get_metrics() -> Response:
    """Prometheus text-format counters for this broker process."""
    return Response(content=metrics.render(), media_type="text/plain; version=0.0.4")
