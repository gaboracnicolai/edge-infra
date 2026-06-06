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
