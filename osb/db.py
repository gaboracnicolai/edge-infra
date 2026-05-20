"""asyncpg connection-pool factory."""

from __future__ import annotations

import asyncpg


async def create_pool(dsn: str) -> asyncpg.Pool:
    """Open a pool sized for the broker (and pgbouncer-compatible)."""
    return await asyncpg.create_pool(
        dsn=dsn,
        min_size=2,
        max_size=10,
        command_timeout=30,
        statement_cache_size=0,
    )
