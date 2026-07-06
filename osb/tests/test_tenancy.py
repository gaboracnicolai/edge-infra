"""R4 Stage 2 — enforced tenant isolation. Cross-tenant DENIAL first.

Real-DB integration (skipped unless TEST_DATABASE_URL); requires the Stage 2
schema (osb/migrations/0002_tenancy.sql) applied. The security property under
test: the caller's tenant comes from the verified per-tenant API key and is the
ONLY tenant — no request body can set or cross it.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import asyncpg
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import worker
from config import Settings

TEST_DB = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    TEST_DB is None, reason="TEST_DATABASE_URL not set (integration only)"
)


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _spec(name="checkout", team="teama", host="10.0.0.1", port=8080) -> dict:
    return {"name": name, "team": team, "host": host, "port": port, "protocol": "HTTP"}


@pytest_asyncio.fixture
async def pool():
    p = await asyncpg.create_pool(TEST_DB, min_size=1, max_size=4)
    try:
        yield p
    finally:
        await p.close()


@pytest_asyncio.fixture(autouse=True)
async def clean(pool):
    async with pool.acquire() as c:
        await c.execute(
            "TRUNCATE services, provision_requests, routes, endpoints, clusters, "
            "gateways, tenant_api_keys RESTART IDENTITY CASCADE"
        )
    yield


@pytest_asyncio.fixture
async def keys(pool):
    """Seed two tenants; return their plaintext bearer keys."""
    ka, kb = "key-a-" + uuid.uuid4().hex, "key-b-" + uuid.uuid4().hex
    async with pool.acquire() as c:
        await c.execute(
            "INSERT INTO tenant_api_keys (key_hash, team) VALUES ($1,'teama'),($2,'teamb')",
            _hash(ka),
            _hash(kb),
        )
    return SimpleNamespace(a=ka, b=kb)


@pytest_asyncio.fixture
async def client(pool):
    """httpx client bound to the FastAPI app with a REAL pool + mock JetStream."""
    from main import app

    app.state.pool = pool
    js = AsyncMock()
    js.publish = AsyncMock(return_value=None)
    app.state.js = js
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        yield c


def _auth(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


# ---- CROSS-TENANT DENIAL (lead) -------------------------------------------

async def test_team_a_cannot_delete_team_b_service(client, keys, pool):
    async with pool.acquire() as c:
        await c.execute(
            "INSERT INTO services (name,team,host,port,protocol) "
            "VALUES ('paydb','teamb','h',80,'HTTP')"
        )
    r = await client.delete("/v1/services/paydb", headers=_auth(keys.a))
    assert r.status_code == 404, r.text  # A cannot even see B's service
    async with pool.acquire() as c:
        row = await c.fetchrow(
            "SELECT deleted_at FROM services WHERE team='teamb' AND name='paydb'"
        )
    assert row is not None and row["deleted_at"] is None  # B untouched


async def test_body_team_is_overwritten_by_caller_tenant(client, keys, pool):
    # A (key -> teama) claims team='teamb' in the body — must be stamped teama.
    r = await client.post(
        "/v1/services", json=_spec(name="svc1", team="teamb"), headers=_auth(keys.a)
    )
    assert r.status_code == 202, r.text
    async with pool.acquire() as c:
        row = await c.fetchrow(
            "SELECT payload::text AS p, team FROM provision_requests "
            "ORDER BY created_at DESC LIMIT 1"
        )
    assert json.loads(row["p"])["team"] == "teama"  # body 'teamb' ignored
    assert row["team"] == "teama"


async def test_team_a_cannot_read_team_b_request(client, keys, pool):
    rid = uuid.uuid4()
    async with pool.acquire() as c:
        await c.execute(
            "INSERT INTO provision_requests (id,operation,status,payload,team) "
            "VALUES ($1,'CREATE','PENDING','{}'::jsonb,'teamb')",
            rid,
        )
    r = await client.get(f"/v1/requests/{rid}", headers=_auth(keys.a))
    assert r.status_code == 404, r.text


# ---- auth resolution ------------------------------------------------------

async def test_auth_absent_bearer_401(client, keys):
    r = await client.delete("/v1/services/paydb")
    assert r.status_code == 401, r.text


async def test_auth_unmapped_bearer_403(client, keys):
    r = await client.delete("/v1/services/paydb", headers=_auth("bogus-unmapped-key"))
    assert r.status_code == 403, r.text


# ---- coexistence: two teams share a name (worker-level) -------------------

async def _create(pool, cfg, spec: dict):
    m = SimpleNamespace(
        subject=cfg.nats_subject_provision,
        data=json.dumps(spec).encode(),
        headers={"Nats-Msg-Id": str(uuid.uuid4())},
        ack=AsyncMock(),
        nak=AsyncMock(),
    )
    await worker.process_message(m, pool, cfg)
    return m


async def test_two_teams_can_share_a_name(pool):
    cfg = Settings()
    for team in ("teama", "teamb"):
        m = await _create(pool, cfg, _spec(name="checkout", team=team))
        m.ack.assert_awaited_once()
        m.nak.assert_not_awaited()
    async with pool.acquire() as c:
        nsvc = await c.fetchval("SELECT count(*) FROM services WHERE name='checkout'")
        ca = await c.fetchrow("SELECT 1 FROM clusters WHERE name='osb-teama-checkout'")
        cb = await c.fetchrow("SELECT 1 FROM clusters WHERE name='osb-teamb-checkout'")
        ngw = await c.fetchval("SELECT count(*) FROM gateways WHERE name='osb-shared-http'")
    assert nsvc == 2  # two services rows, same name, different team
    assert ca is not None and cb is not None  # distinct derived clusters
    assert ngw == 1  # shared gateway is a singleton, never per-tenant


async def test_delete_is_team_scoped(pool):
    # A and B both have 'checkout'; deleting A's must leave B's intact.
    cfg = Settings()
    await _create(pool, cfg, _spec(name="checkout", team="teama"))
    await _create(pool, cfg, _spec(name="checkout", team="teamb"))
    m = SimpleNamespace(
        subject=cfg.nats_subject_deprovision,
        data=json.dumps({"team": "teama", "name": "checkout"}).encode(),
        headers={"Nats-Msg-Id": str(uuid.uuid4())},
        ack=AsyncMock(),
        nak=AsyncMock(),
    )
    await worker.process_message(m, pool, cfg)
    m.ack.assert_awaited_once()
    async with pool.acquire() as c:
        a_route = await c.fetchrow("SELECT deleted_at FROM routes WHERE name='osb-teama-checkout'")
        b_route = await c.fetchrow("SELECT deleted_at FROM routes WHERE name='osb-teamb-checkout'")
        a_cluster = await c.fetchrow("SELECT 1 FROM clusters WHERE name='osb-teama-checkout'")
        b_cluster = await c.fetchrow("SELECT 1 FROM clusters WHERE name='osb-teamb-checkout'")
    assert a_route is not None and a_route["deleted_at"] is not None  # A's route dropped
    assert a_cluster is None  # A's cluster hard-deleted
    assert b_route is not None and b_route["deleted_at"] is None  # B untouched
    assert b_cluster is not None


async def test_delete_derives_name_from_caller_team_not_stored_row(pool):
    """Defense-in-depth: the derived name comes from the caller's authenticated
    team, never a name-only lookup of the services table. Only team B owns
    'checkout'; a worker DELETE for (teamA, 'checkout') must derive
    osb-teama-checkout — a no-op — and leave team B's osb-teamb-checkout fully
    served. (A name-only `SELECT team ... WHERE name='checkout'` would resolve to
    teamB and wrongly unwind B's rows — this asserts that can't happen.)
    """
    cfg = Settings()
    await _create(pool, cfg, _spec(name="checkout", team="teamb"))
    m = SimpleNamespace(
        subject=cfg.nats_subject_deprovision,
        data=json.dumps({"team": "teama", "name": "checkout"}).encode(),
        headers={"Nats-Msg-Id": str(uuid.uuid4())},
        ack=AsyncMock(),
        nak=AsyncMock(),
    )
    await worker.process_message(m, pool, cfg)
    m.ack.assert_awaited_once()
    async with pool.acquire() as c:
        b_route = await c.fetchrow("SELECT deleted_at FROM routes WHERE name='osb-teamb-checkout'")
        b_cluster = await c.fetchrow("SELECT 1 FROM clusters WHERE name='osb-teamb-checkout'")
        a_cluster = await c.fetchrow("SELECT 1 FROM clusters WHERE name='osb-teama-checkout'")
    assert b_route is not None and b_route["deleted_at"] is None  # B fully served
    assert b_cluster is not None
    assert a_cluster is None  # no team-A rows ever existed; A's delete touched nothing


# ---- fail-closed startup (L3) ---------------------------------------------

async def test_startup_refuses_without_keys_when_untenanted_false(pool):
    from main import startup_tenancy_check

    cfg = Settings()  # OSB_ALLOW_UNTENANTED defaults false; tenant_api_keys empty
    with pytest.raises(RuntimeError):
        await startup_tenancy_check(pool, cfg)


async def test_startup_ok_when_allow_untenanted(pool, monkeypatch):
    from main import startup_tenancy_check

    cfg = Settings()
    monkeypatch.setattr(cfg, "allow_untenanted", True)
    await startup_tenancy_check(pool, cfg)  # must not raise even with no keys
