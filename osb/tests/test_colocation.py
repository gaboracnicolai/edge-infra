"""R4 co-location self-check (fail-closed) — OSB side, mirroring the Go
store.VerifyColocation."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock

import asyncpg
import pytest
import pytest_asyncio

from db import verify_colocation

TEST_DB = os.getenv("TEST_DATABASE_URL")


def _pool(osb: bool, cp: bool) -> AsyncMock:
    pool = AsyncMock()
    pool.fetchrow = AsyncMock(return_value={"osb": osb, "cp": cp})
    return pool


# Co-located: both the OSB (services) and control-plane (gateways) schemas are in
# the one DB → OSB starts.
async def test_colocated_starts():
    await verify_colocation(_pool(osb=True, cp=True))  # must not raise


# Divergent: the control-plane schema is absent (OSB pointed at a DB the CP is
# not) → refuse to start.
async def test_missing_control_plane_schema_refuses():
    with pytest.raises(RuntimeError):
        await verify_colocation(_pool(osb=True, cp=False))


# Divergent: the OSB schema is absent → refuse to start.
async def test_missing_osb_schema_refuses():
    with pytest.raises(RuntimeError):
        await verify_colocation(_pool(osb=False, cp=True))


# --- real-DB happy path (integration): validates the to_regclass SQL + aliases
# against a real Postgres — a mock can't catch a SQL typo. -----------------------


@pytest_asyncio.fixture
async def real_pool():
    if not TEST_DB:
        pytest.skip("TEST_DATABASE_URL required (integration)")
    p = await asyncpg.create_pool(TEST_DB, min_size=1, max_size=2)
    try:
        yield p
    finally:
        await p.close()


# The harness DB has BOTH schemas (co-located) → verify_colocation passes.
async def test_colocation_passes_on_real_colocated_db(real_pool):
    await verify_colocation(real_pool)  # must not raise
