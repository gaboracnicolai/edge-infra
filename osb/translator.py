"""Derive control-plane (xDS) rows from an OSB ServiceSpec — R4 Stage 1.

A registered HTTP service is fanned out into the shared gateway plus a
per-service cluster + endpoint + route, so the Go reconciler's LoadSnapshot
serves it as a listener/route/cluster/endpoint. All writes take a caller-owned
asyncpg connection and run inside the caller's transaction, alongside the
``services`` row — a partial failure rolls the whole provision back, so no
half-built config ever reaches Envoy.

Disjointness from controller-written rows is by the ``osb-{team}-`` name prefix
(controllers write user-chosen names). A formal owner column + UNIQUE(team,name)
is Stage 2 and intentionally not added here.

HTTPS is out of Stage 1 scope: the caller still writes the ``services`` row, but
no data-plane rows are produced (per-SNI TLS + builder work is Stage 3). The
deferral is signalled by the ``deferred_https`` outcome, never silent.
"""

from __future__ import annotations

from typing import Literal

import structlog

from models import ServiceSpec

log = structlog.get_logger(__name__)

# Fixed identity of the shared public HTTP listener (port 80 matches the
# edge-proxy DaemonSet hostPort). Seeded idempotently on first fan-out.
SHARED_HTTP_GATEWAY = "osb-shared-http"

_DEFAULT_CONNECT_TIMEOUT_MS = 5000
_DEFAULT_LB_POLICY = "ROUND_ROBIN"
_DEFAULT_ROUTE_TIMEOUT_S = 30

CreateOutcome = Literal["provisioned", "deferred_https"]


def derived_name(team: str, name: str) -> str:
    """The osb-namespaced identity shared by the derived cluster and route.

    Both ``team`` and ``name`` are validated slugs (SERVICE_NAME_PATTERN), so the
    result is a safe, collision-resistant identifier disjoint from controller
    rows during coexistence.
    """
    return f"osb-{team}-{name}"


async def apply_create(conn, spec: ServiceSpec) -> CreateOutcome:
    """Fan an HTTP service out into gateway + cluster + endpoint + route.

    Runs on the caller's connection inside the caller's transaction. HTTPS is
    deferred: returns ``deferred_https`` and writes no data-plane rows.
    """
    if spec.protocol != "HTTP":
        log.info(
            "osb https service: data-plane fan-out deferred to stage 3",
            service=spec.name,
            team=spec.team,
        )
        return "deferred_https"

    dn = derived_name(spec.team, spec.name)

    # 1. Ensure the shared HTTP gateway exists (idempotent; never per-service).
    await conn.execute(
        """
        INSERT INTO gateways (id, name, port, protocol, node_selector)
        VALUES ($1, $1, 80, 'HTTP', '{}'::jsonb)
        ON CONFLICT (name) DO NOTHING
        """,
        SHARED_HTTP_GATEWAY,
    )

    # 2. Per-service cluster (EDS; endpoints attached below).
    await conn.execute(
        """
        INSERT INTO clusters (id, name, connect_timeout_ms, lb_policy)
        VALUES ($1, $1, $2, $3)
        ON CONFLICT (name) DO UPDATE SET
            connect_timeout_ms = EXCLUDED.connect_timeout_ms,
            lb_policy          = EXCLUDED.lb_policy,
            updated_at         = NOW()
        """,
        dn,
        _DEFAULT_CONNECT_TIMEOUT_MS,
        _DEFAULT_LB_POLICY,
    )

    # 3. Endpoint — one per service. Replace so a changed host/port leaves no
    #    orphan (endpoints have no soft-delete; the whole op is in one tx).
    await conn.execute("DELETE FROM endpoints WHERE cluster_id = $1", dn)
    await conn.execute(
        """
        INSERT INTO endpoints (id, cluster_id, address, port, weight)
        VALUES ($1, $2, $3, $4, 1)
        """,
        f"{dn}-0",
        dn,
        spec.host,
        spec.port,
    )

    # 4. Route on the shared gateway, forwarding to the cluster by name.
    await conn.execute(
        """
        INSERT INTO routes
            (id, name, gateway_id, hosts, path_prefix, cluster_name, timeout_seconds, deleted_at)
        VALUES ($1, $1, $2, $3::text[], '/', $1, $4, NULL)
        ON CONFLICT (name) DO UPDATE SET
            gateway_id      = EXCLUDED.gateway_id,
            hosts           = EXCLUDED.hosts,
            path_prefix     = EXCLUDED.path_prefix,
            cluster_name    = EXCLUDED.cluster_name,
            timeout_seconds = EXCLUDED.timeout_seconds,
            updated_at      = NOW(),
            deleted_at      = NULL
        """,
        dn,
        SHARED_HTTP_GATEWAY,
        [spec.host],
        _DEFAULT_ROUTE_TIMEOUT_S,
    )

    log.info("osb http service fanned out", service=spec.name, team=spec.team, cluster=dn)
    return "provisioned"


async def apply_delete(conn, team: str, name: str) -> bool:
    """Unwind a service's derived rows for the given tenant: soft-delete the
    route (so it drops from the snapshot) and hard-delete the cluster (cascading
    its endpoints; clusters have no soft-delete). The shared gateway is never
    removed.

    ``team`` is the caller's authenticated tenant (threaded from the API through
    the NATS payload); the derived name is built from IT — there is NO name-only
    lookup, so a caller can only ever unwind its own ``osb-{team}-{name}`` rows,
    even when another tenant owns a service with the same name.

    Existence is keyed on the tenant-scoped services row (``WHERE team AND name``,
    never a name-only match); returns False as a no-op when this tenant has no
    such service (idempotent).
    """
    owned = await conn.fetchrow(
        "SELECT 1 FROM services WHERE team = $1 AND name = $2", team, name
    )
    if owned is None:
        return False

    dn = derived_name(team, name)
    await conn.execute(
        "UPDATE routes SET deleted_at = NOW(), updated_at = NOW() "
        "WHERE name = $1 AND deleted_at IS NULL",
        dn,
    )
    await conn.execute("DELETE FROM clusters WHERE name = $1", dn)
    return True
