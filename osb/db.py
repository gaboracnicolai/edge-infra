"""asyncpg connection-pool factory."""

from __future__ import annotations

import asyncpg

from tls import build_pg_ssl


async def create_pool(
    dsn: str,
    *,
    ssl_mode: str = "require",
    ca_path: str | None = None,
) -> asyncpg.Pool:
    """Open a pool sized for the broker (and pgbouncer-compatible).

    TLS is controlled by ``ssl_mode`` (libpq sslmode semantics). Production uses
    ``verify-full`` with ``ca_path`` pointing at the internal cert-manager CA so
    the server certificate and hostname are both verified (ISO 27001 A.13).
    """
    ssl_arg = build_pg_ssl(ssl_mode, ca_path)
    return await asyncpg.create_pool(
        dsn=dsn,
        min_size=2,
        max_size=10,
        command_timeout=30,
        statement_cache_size=0,
        ssl=ssl_arg,
    )


async def verify_colocation(pool) -> None:
    """R4 co-location invariant (fail-closed): edge-osb and the control-plane MUST
    share ONE database. Refuse to start if the connected DB is missing either the
    OSB schema (services) or the control-plane schema (gateways) — a divergent DSN
    is a misconfiguration, not a runtime state. Mirrors the Go
    store.VerifyColocation so the invariant is enforced from both sides.
    """
    row = await pool.fetchrow(
        "SELECT to_regclass('public.services') IS NOT NULL AS osb, "
        "       to_regclass('public.gateways') IS NOT NULL AS cp"
    )
    if not row["osb"] or not row["cp"]:
        raise RuntimeError(
            "co-location invariant violated: the shared database must contain BOTH "
            f"the OSB schema (services present={row['osb']}) and the control-plane "
            f"schema (gateways present={row['cp']}) — edge-osb and the control-plane "
            "must point at the SAME database"
        )
