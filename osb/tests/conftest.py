"""Shared async fixtures for OSB tests."""

from __future__ import annotations

import sys
from collections.abc import AsyncIterator
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# Make the osb/ source modules importable when running tests in-place.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import Settings  # noqa: E402


@pytest.fixture
def cfg() -> Settings:
    """Settings instance with library defaults — no real DB/NATS required."""
    return Settings()


@pytest.fixture
def mock_pool() -> AsyncMock:
    """asyncpg.Pool double — execute/fetchrow are awaitable and return None by default."""
    pool = AsyncMock()
    pool.execute = AsyncMock(return_value=None)
    pool.fetchrow = AsyncMock(return_value=None)
    return pool


@pytest.fixture
def mock_js() -> AsyncMock:
    """JetStream double — publish is awaitable, returns None."""
    js = AsyncMock()
    js.publish = AsyncMock(return_value=None)
    return js


@pytest_asyncio.fixture
async def app_client(mock_pool: AsyncMock, mock_js: AsyncMock) -> AsyncIterator[AsyncClient]:
    """An httpx AsyncClient bound to the FastAPI app via ASGITransport.

    ASGITransport does not run lifespan events, so we wire the pool and js
    handles directly onto app.state for each test.
    """
    from main import app

    app.state.pool = mock_pool
    app.state.js = mock_js

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
