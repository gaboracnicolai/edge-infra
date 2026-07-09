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
import specvalidation
from config import Settings
from db import create_pool, verify_colocation
from models import ProvisionRequest, ProvisionResponse, ServiceSpec
from security import (
    RequestIDMiddleware,
    SecurityHeadersMiddleware,
    admin_key_ok,
    bearer_token,
    hash_key,
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
    await verify_colocation(pool)  # fail-closed: refuse if not co-located with the control-plane
    await startup_tenancy_check(pool, cfg)  # fail-closed: refuse to start unconfigured
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


async def require_tenant(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    x_tenant: Annotated[str | None, Header()] = None,
) -> str:
    """Resolve the caller's tenant from the verified per-tenant API key (A.9).

    The returned team is the ONLY tenant for the request — the body can never set
    or cross it. 401 when no bearer is presented, 403 when the bearer is
    unrecognized. In explicit open mode (OSB_ALLOW_UNTENANTED=true, dev only) an
    unresolved caller falls back to the X-Tenant header or "default".
    """
    token = bearer_token(authorization)
    if token is not None:
        row = await request.app.state.pool.fetchrow(
            "SELECT team FROM tenant_api_keys WHERE key_hash = $1", hash_key(token)
        )
        if row is not None:
            return row["team"]
        if not cfg.allow_untenanted:
            raise HTTPException(status_code=403, detail="unrecognized API key")
    elif not cfg.allow_untenanted:
        raise HTTPException(status_code=401, detail="API key required")
    return x_tenant or "default"  # explicit open/dev mode only


async def startup_tenancy_check(pool, settings: Settings) -> None:
    """Fail closed: refuse to start when tenant isolation is unconfigured.

    With OSB_ALLOW_UNTENANTED false (default) and no rows in tenant_api_keys,
    every provisioning call would be unauthenticated — so refuse to start rather
    than silently run open (like R1 ext_authz's fail-closed posture). Set the
    flag true (dev) to bypass.
    """
    if settings.allow_untenanted:
        log.warning(
            "OSB_ALLOW_UNTENANTED=true — provisioning runs WITHOUT tenant isolation (dev only)"
        )
        return
    count = await pool.fetchval("SELECT count(*) FROM tenant_api_keys")
    if not count:
        raise RuntimeError(
            "no tenant_api_keys configured and OSB_ALLOW_UNTENANTED is false — "
            "refusing to start (populate tenant_api_keys or set OSB_ALLOW_UNTENANTED=true for dev)"
        )


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


@app.post("/v1/services", status_code=202, response_model=ProvisionResponse)
async def create_service(
    spec: ServiceSpec,
    request: Request,
    tenant: Annotated[str, Depends(require_tenant)],
) -> ProvisionResponse:
    """Enqueue a CREATE request. The caller's authenticated tenant is
    authoritative — the body's ``team`` is overwritten, so a caller can never
    write into another tenant's namespace (R4 Stage 2, L2)."""
    spec.team = tenant
    try:
        return await broker.provision(
            spec, request.app.state.pool, request.app.state.js, cfg, tenant
        )
    except Exception as exc:  # noqa: BLE001 — every broker failure becomes a 500
        log.exception("provision failed", error=str(exc))
        raise HTTPException(status_code=500, detail="failed to queue provision") from exc


@app.delete("/v1/services/{name}", status_code=202, response_model=ProvisionResponse)
async def delete_service(
    name: str,
    request: Request,
    tenant: Annotated[str, Depends(require_tenant)],
) -> ProvisionResponse:
    """Enqueue a DELETE for the caller's OWN service. Deleting a name the tenant
    does not own returns 404 — cross-tenant existence is never revealed."""
    # The {name} path param skips ServiceSpec validation, so enforce the same
    # name shape here — it flows into SQL params and the NATS payload (A.14).
    try:
        specvalidation.validate_service_name(name)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    pool = request.app.state.pool
    owned = await pool.fetchrow(
        "SELECT 1 FROM services WHERE team = $1 AND name = $2 AND deleted_at IS NULL",
        tenant,
        name,
    )
    if owned is None:
        raise HTTPException(status_code=404, detail="service not found")
    try:
        return await broker.deprovision(name, pool, request.app.state.js, cfg, tenant)
    except Exception as exc:  # noqa: BLE001
        log.exception("deprovision failed", error=str(exc))
        raise HTTPException(status_code=500, detail="failed to queue deprovision") from exc


@app.get("/v1/requests/{request_id}", response_model=ProvisionRequest)
async def get_request(
    request_id: UUID,
    request: Request,
    tenant: Annotated[str, Depends(require_tenant)],
) -> ProvisionRequest:
    """Return a provisioning request — scoped to the caller's tenant; another
    tenant's request UUID returns 404."""
    row = await request.app.state.pool.fetchrow(
        """
        SELECT id, operation, status, payload::text AS payload, webhook_url,
               error, completed_at, created_at
        FROM provision_requests
        WHERE id = $1 AND team = $2
        """,
        request_id,
        tenant,
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
