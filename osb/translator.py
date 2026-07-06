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

HTTPS (R4 Stage 3b-i): a service is fanned out onto the shared HTTPS listener
(port 443), with the route carrying its ``tls_secret_name`` — a REFERENCE only.
OSB never writes the cert/key material (the Stage 1 boundary); the secret must be
provisioned separately (sub-stage 2), and SDS resolves it by name at render time.
mtls / jwt_or_mtls transport auth remain later sub-stages.
"""

from __future__ import annotations

from typing import Literal

import structlog

from models import ServiceSpec

log = structlog.get_logger(__name__)

# Fixed identity of the shared public listeners (ports match the edge-proxy
# DaemonSet hostPorts). Seeded idempotently on first fan-out. The HTTPS gateway
# carries NO tls_secret — per-SNI certs live on the routes.
SHARED_HTTP_GATEWAY = "osb-shared-http"
SHARED_HTTPS_GATEWAY = "osb-shared-https"

_DEFAULT_CONNECT_TIMEOUT_MS = 5000
_DEFAULT_LB_POLICY = "ROUND_ROBIN"
_DEFAULT_ROUTE_TIMEOUT_S = 30

CreateOutcome = Literal["provisioned", "provisioned_https"]


def derived_name(team: str, name: str) -> str:
    """The osb-namespaced identity shared by the derived cluster and route.

    Both ``team`` and ``name`` are validated slugs (SERVICE_NAME_PATTERN), so the
    result is a safe, collision-resistant identifier disjoint from controller
    rows during coexistence.
    """
    return f"osb-{team}-{name}"


async def apply_create(conn, spec: ServiceSpec) -> CreateOutcome:
    """Fan a service out into gateway + cluster + endpoint + route.

    Runs on the caller's connection inside the caller's transaction. HTTP lands on
    the shared ``osb-shared-http:80`` listener; HTTPS on ``osb-shared-https:443``
    with the route carrying its ``tls_secret_name`` — a REFERENCE only; OSB never
    writes cert/key material (SDS resolves the secret by name).
    """
    dn = derived_name(spec.team, spec.name)
    if spec.protocol == "HTTPS":
        gateway, port, protocol, tls_secret, outcome = (
            SHARED_HTTPS_GATEWAY,
            443,
            "HTTPS",
            spec.tls_secret_name,  # reference only; the material lives in `secrets`
            "provisioned_https",
        )
    else:
        gateway, port, protocol, tls_secret, outcome = (
            SHARED_HTTP_GATEWAY,
            80,
            "HTTP",
            None,
            "provisioned",
        )

    # 1. Ensure the shared gateway exists (idempotent; never per-service). The
    #    HTTPS gateway carries NO tls_secret — per-SNI certs live on the routes.
    await conn.execute(
        """
        INSERT INTO gateways (id, name, port, protocol, node_selector)
        VALUES ($1, $1, $2, $3, '{}'::jsonb)
        ON CONFLICT (name) DO NOTHING
        """,
        gateway,
        port,
        protocol,
    )

    # 2. Per-service cluster (EDS; endpoints attached below). The health_check
    #    columns carry the service's active HTTP check; ON CONFLICT sets them
    #    from EXCLUDED so a re-CREATE that drops health_check NULLs them (no stale
    #    check served).
    await conn.execute(
        """
        INSERT INTO clusters (id, name, connect_timeout_ms, lb_policy,
                              health_check_path, health_check_interval_s)
        VALUES ($1, $1, $2, $3, $4, $5)
        ON CONFLICT (name) DO UPDATE SET
            connect_timeout_ms      = EXCLUDED.connect_timeout_ms,
            lb_policy               = EXCLUDED.lb_policy,
            health_check_path       = EXCLUDED.health_check_path,
            health_check_interval_s = EXCLUDED.health_check_interval_s,
            updated_at              = NOW()
        """,
        dn,
        _DEFAULT_CONNECT_TIMEOUT_MS,
        _DEFAULT_LB_POLICY,
        spec.health_check.path if spec.health_check else None,
        spec.health_check.interval_seconds if spec.health_check else None,
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

    # 4. Route on the shared gateway, forwarding to the cluster by name. The
    #    rate_limit / auth_policy / tls_secret_name columns carry the per-route
    #    policy + (for HTTPS) the SNI cert REFERENCE; ON CONFLICT sets them from
    #    EXCLUDED so a re-CREATE that drops a value clears it (no stale policy).
    #    tls_secret_name is a reference ONLY — never key material.
    await conn.execute(
        """
        INSERT INTO routes
            (id, name, gateway_id, hosts, path_prefix, cluster_name, timeout_seconds,
             rate_limit_per_unit, rate_limit_unit, auth_policy, tls_secret_name, deleted_at)
        VALUES ($1, $1, $2, $3::text[], '/', $1, $4, $5, $6, $7, $8, NULL)
        ON CONFLICT (name) DO UPDATE SET
            gateway_id          = EXCLUDED.gateway_id,
            hosts               = EXCLUDED.hosts,
            path_prefix         = EXCLUDED.path_prefix,
            cluster_name        = EXCLUDED.cluster_name,
            timeout_seconds     = EXCLUDED.timeout_seconds,
            rate_limit_per_unit = EXCLUDED.rate_limit_per_unit,
            rate_limit_unit     = EXCLUDED.rate_limit_unit,
            auth_policy         = EXCLUDED.auth_policy,
            tls_secret_name     = EXCLUDED.tls_secret_name,
            updated_at          = NOW(),
            deleted_at          = NULL
        """,
        dn,
        gateway,
        [spec.host],
        _DEFAULT_ROUTE_TIMEOUT_S,
        spec.rate_limit.requests_per_unit if spec.rate_limit else None,
        spec.rate_limit.unit if spec.rate_limit else None,
        spec.auth_policy,
        tls_secret,
    )

    log.info(
        "osb service fanned out",
        service=spec.name, team=spec.team, cluster=dn, protocol=spec.protocol,
    )
    return outcome


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
