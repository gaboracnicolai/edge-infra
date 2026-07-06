"""Integration tests for the OSB -> data-plane translator (R4 Stage 1).

These drive the real worker.process_message against a REAL Postgres holding BOTH
schemas (control-plane migrations/*.sql + osb/migrations/*.sql). They are skipped
unless TEST_DATABASE_URL is set, so the default mock-based suite is unaffected.

Run via: make test-integration  (stands up Postgres, applies both schemas, sets
TEST_DATABASE_URL).
"""

from __future__ import annotations

import json
import os
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import asyncpg
import pytest
import pytest_asyncio

import metrics
import worker
from config import Settings
from models import ServiceSpec

TEST_DB = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    TEST_DB is None, reason="TEST_DATABASE_URL not set (integration only)"
)


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
            "TRUNCATE services, provision_requests, routes, endpoints, clusters, gateways, secrets "
            "RESTART IDENTITY CASCADE"
        )
    yield


@pytest.fixture
def cfg() -> Settings:
    return Settings()


def _msg(subject: str, data: bytes):
    m = SimpleNamespace()
    m.subject = subject
    m.data = data
    m.headers = {"Nats-Msg-Id": str(uuid.uuid4())}
    m.ack = AsyncMock()
    m.nak = AsyncMock()
    return m


def _http_spec(name="checkout", team="payments", host="10.0.0.5", port=8080) -> ServiceSpec:
    return ServiceSpec(name=name, team=team, host=host, port=port, protocol="HTTP")


async def _create(pool, cfg, spec: ServiceSpec):
    m = _msg(cfg.nats_subject_provision, spec.model_dump_json().encode())
    await worker.process_message(m, pool, cfg)
    return m


async def _delete(pool, cfg, team: str, name: str):
    m = _msg(cfg.nats_subject_deprovision, json.dumps({"team": team, "name": name}).encode())
    await worker.process_message(m, pool, cfg)
    return m


# 1. CREATE fans an HTTP service out into gateway + cluster + endpoint + route.
async def test_create_http_fans_out(pool, cfg):
    m = await _create(pool, cfg, _http_spec())
    async with pool.acquire() as c:
        gw = await c.fetchrow("SELECT port, protocol FROM gateways WHERE name='osb-shared-http'")
        cl = await c.fetchrow("SELECT lb_policy FROM clusters WHERE name='osb-payments-checkout'")
        ep = await c.fetchrow(
            "SELECT address, port FROM endpoints WHERE cluster_id='osb-payments-checkout'"
        )
        rt = await c.fetchrow(
            "SELECT gateway_id, cluster_name, hosts, path_prefix, deleted_at "
            "FROM routes WHERE name='osb-payments-checkout'"
        )
    assert gw is not None and gw["port"] == 80 and gw["protocol"] == "HTTP"
    assert cl is not None
    assert ep is not None and ep["address"] == "10.0.0.5" and ep["port"] == 8080
    assert rt is not None
    assert rt["gateway_id"] == "osb-shared-http"
    assert rt["cluster_name"] == "osb-payments-checkout"
    assert rt["path_prefix"] == "/"
    assert list(rt["hosts"]) == ["10.0.0.5"]
    assert rt["deleted_at"] is None
    m.ack.assert_awaited_once()
    m.nak.assert_not_awaited()


# 2. DELETE soft-deletes the route, hard-deletes cluster+endpoint, keeps the
#    shared gateway, and soft-deletes the services row.
async def test_delete_soft_route_hard_cluster(pool, cfg):
    await _create(pool, cfg, _http_spec())
    await _delete(pool, cfg, "payments", "checkout")
    async with pool.acquire() as c:
        rt = await c.fetchrow("SELECT deleted_at FROM routes WHERE name='osb-payments-checkout'")
        cl = await c.fetchrow("SELECT 1 FROM clusters WHERE name='osb-payments-checkout'")
        ep = await c.fetchrow("SELECT 1 FROM endpoints WHERE cluster_id='osb-payments-checkout'")
        gw = await c.fetchrow("SELECT 1 FROM gateways WHERE name='osb-shared-http'")
        svc = await c.fetchrow("SELECT deleted_at FROM services WHERE name='checkout'")
    assert rt is not None and rt["deleted_at"] is not None  # route soft-deleted
    assert cl is None and ep is None  # cluster+endpoint hard-deleted (cascade)
    assert gw is not None                                   # shared gateway persists
    assert svc is not None and svc["deleted_at"] is not None


# 3. Re-CREATE with the same spec is idempotent — one row per resource, no error.
async def test_recreate_idempotent(pool, cfg):
    await _create(pool, cfg, _http_spec())
    await _create(pool, cfg, _http_spec())
    async with pool.acquire() as c:
        counts = await c.fetchrow(
            """
            SELECT (SELECT count(*) FROM gateways WHERE name='osb-shared-http')          AS gw,
                   (SELECT count(*) FROM clusters WHERE name='osb-payments-checkout')    AS cl,
                   (SELECT count(*) FROM endpoints WHERE cluster_id='osb-payments-checkout') AS ep,
                   (SELECT count(*) FROM routes WHERE name='osb-payments-checkout')      AS rt
            """
        )
    assert (counts["gw"], counts["cl"], counts["ep"], counts["rt"]) == (1, 1, 1, 1)


# 4. HTTPS now provisions per-SNI (3b-i): the shared HTTPS gateway (443, no cert)
#    + cluster + endpoint + a route carrying tls_secret_name (REFERENCE only).
#    OSB writes NO cert material; the provisioned_https metric fires.
async def test_https_provisions_per_sni(pool, cfg):
    spec = ServiceSpec(
        name="secure", team="payments", host="secure.example.com", port=8443,
        protocol="HTTPS", tls_secret_name="edge-cert",
    )
    before = metrics.services_derived_total[("HTTPS", "provisioned_https")]
    await _create(pool, cfg, spec)
    async with pool.acquire() as c:
        gw = await c.fetchrow(
            "SELECT port, protocol, tls_secret FROM gateways WHERE name='osb-shared-https'"
        )
        cl = await c.fetchrow("SELECT 1 FROM clusters WHERE name='osb-payments-secure'")
        ep = await c.fetchrow(
            "SELECT address FROM endpoints WHERE cluster_id='osb-payments-secure'"
        )
        rt = await c.fetchrow(
            "SELECT gateway_id, hosts, tls_secret_name FROM routes WHERE name='osb-payments-secure'"
        )
        cert_row = await c.fetchrow("SELECT 1 FROM secrets WHERE name='edge-cert'")
    assert gw is not None and gw["port"] == 443 and gw["protocol"] == "HTTPS"
    assert gw["tls_secret"] is None  # shared HTTPS gateway carries NO cert — per-SNI on routes
    assert cl is not None and ep is not None
    assert rt is not None and rt["gateway_id"] == "osb-shared-https"
    assert list(rt["hosts"]) == ["secure.example.com"]  # the SNI host
    assert rt["tls_secret_name"] == "edge-cert"  # reference stamped on the route
    assert cert_row is None  # BOUNDARY: OSB referenced the secret but never wrote it
    assert metrics.services_derived_total[("HTTPS", "provisioned_https")] == before + 1


# --- adversarial (green-locking) -------------------------------------------

# Partial-tx failure: a mid-fan-out error rolls the WHOLE transaction back — no
# services row, no orphan cluster/route. Proven by injecting a failure.
async def test_partial_failure_rolls_back_everything(pool, cfg, monkeypatch):
    import translator

    real = translator.apply_create

    async def boom(conn, spec):
        await real(conn, spec)          # writes gateway+cluster+endpoint+route
        raise RuntimeError("injected mid-transaction failure")

    monkeypatch.setattr(worker.translator, "apply_create", boom)
    m = await _create(pool, cfg, _http_spec(name="rollback", team="ops"))
    async with pool.acquire() as c:
        svc = await c.fetchrow("SELECT 1 FROM services WHERE name='rollback'")
        cl = await c.fetchrow("SELECT 1 FROM clusters WHERE name='osb-ops-rollback'")
        rt = await c.fetchrow("SELECT 1 FROM routes WHERE name='osb-ops-rollback'")
    assert svc is None and cl is None and rt is None  # entire tx rolled back
    m.nak.assert_awaited_once()
    m.ack.assert_not_awaited()


# DELETE of a never-provisioned service is an idempotent no-op that still acks.
async def test_delete_absent_is_noop(pool, cfg):
    m = await _delete(pool, cfg, "payments", "ghost")
    m.ack.assert_awaited_once()
    m.nak.assert_not_awaited()


# --- Stage 3a-i: per-service rate_limit + health_check on the derived rows -----

# 5. rate_limit + health_check are persisted onto the derived route / cluster.
async def test_policy_persisted_on_derived_rows(pool, cfg):
    spec = ServiceSpec(
        name="checkout", team="payments", host="10.0.0.5", port=8080, protocol="HTTP",
        rate_limit={"requests_per_unit": 100, "unit": "SECOND"},
        health_check={"path": "/healthz", "interval_seconds": 5},
    )
    await _create(pool, cfg, spec)
    async with pool.acquire() as c:
        rt = await c.fetchrow(
            "SELECT rate_limit_per_unit, rate_limit_unit FROM routes "
            "WHERE name='osb-payments-checkout'"
        )
        cl = await c.fetchrow(
            "SELECT health_check_path, health_check_interval_s FROM clusters "
            "WHERE name='osb-payments-checkout'"
        )
    assert rt["rate_limit_per_unit"] == 100 and rt["rate_limit_unit"] == "SECOND"
    assert cl["health_check_path"] == "/healthz" and cl["health_check_interval_s"] == 5


# 6. A service without policy leaves the columns NULL (controller rows unchanged).
async def test_policy_absent_leaves_null(pool, cfg):
    await _create(pool, cfg, _http_spec(name="plain", team="ops"))
    async with pool.acquire() as c:
        rt = await c.fetchrow(
            "SELECT rate_limit_per_unit, rate_limit_unit FROM routes WHERE name='osb-ops-plain'"
        )
        cl = await c.fetchrow(
            "SELECT health_check_path, health_check_interval_s FROM clusters "
            "WHERE name='osb-ops-plain'"
        )
    assert rt["rate_limit_per_unit"] is None and rt["rate_limit_unit"] is None
    assert cl["health_check_path"] is None and cl["health_check_interval_s"] is None


# 7. A re-CREATE that drops the policy NULLs the columns (no stale limit/check).
async def test_policy_removed_on_recreate_nulls_columns(pool, cfg):
    with_policy = ServiceSpec(
        name="drift", team="payments", host="10.0.0.5", port=8080, protocol="HTTP",
        rate_limit={"requests_per_unit": 50, "unit": "MINUTE"},
        health_check={"path": "/hz", "interval_seconds": 10},
    )
    await _create(pool, cfg, with_policy)
    await _create(pool, cfg, _http_spec(name="drift", team="payments"))  # policy dropped
    async with pool.acquire() as c:
        rt = await c.fetchrow(
            "SELECT rate_limit_per_unit FROM routes WHERE name='osb-payments-drift'"
        )
        cl = await c.fetchrow(
            "SELECT health_check_path FROM clusters WHERE name='osb-payments-drift'"
        )
    assert rt["rate_limit_per_unit"] is None  # stale limit cleared
    assert cl["health_check_path"] is None  # stale health check cleared


# --- Stage 3a-ii: per-service auth_policy on the derived route -----------------

# 8. Default auth_policy (jwt) is persisted → the route is authenticated.
async def test_auth_policy_default_jwt_persisted(pool, cfg):
    await _create(pool, cfg, _http_spec(name="apisvc", team="payments"))
    async with pool.acquire() as c:
        ap = await c.fetchval("SELECT auth_policy FROM routes WHERE name='osb-payments-apisvc'")
    assert ap == "jwt"


# 9. Explicit auth_policy=none is persisted → the route opts out of auth.
async def test_auth_policy_none_persisted(pool, cfg):
    spec = ServiceSpec(
        name="public", team="payments", host="10.0.0.5", port=8080,
        protocol="HTTP", auth_policy="none",
    )
    await _create(pool, cfg, spec)
    async with pool.acquire() as c:
        ap = await c.fetchval("SELECT auth_policy FROM routes WHERE name='osb-payments-public'")
    assert ap == "none"


# 10. Re-CREATE flips auth jwt→none→jwt (ON CONFLICT = EXCLUDED); never stale.
async def test_auth_policy_flips_on_recreate(pool, cfg):
    await _create(pool, cfg, _http_spec(name="flip", team="ops"))  # default jwt
    await _create(
        pool, cfg,
        ServiceSpec(name="flip", team="ops", host="10.0.0.5", port=8080,
                    protocol="HTTP", auth_policy="none"),
    )
    async with pool.acquire() as c:
        ap1 = await c.fetchval("SELECT auth_policy FROM routes WHERE name='osb-ops-flip'")
    assert ap1 == "none"
    await _create(pool, cfg, _http_spec(name="flip", team="ops"))  # back to default jwt
    async with pool.acquire() as c:
        ap2 = await c.fetchval("SELECT auth_policy FROM routes WHERE name='osb-ops-flip'")
    assert ap2 == "jwt"


# The osb-{team}- prefix keeps derived rows disjoint from controller-written
# rows: a controller cluster with a user-chosen name is never touched.
async def test_controller_rows_untouched(pool, cfg):
    async with pool.acquire() as c:
        await c.execute(
            "INSERT INTO clusters (id, name, connect_timeout_ms, lb_policy) "
            "VALUES ('team-owned', 'team-owned', 1234, 'MAGLEV')"
        )
    await _create(pool, cfg, _http_spec())
    async with pool.acquire() as c:
        row = await c.fetchrow(
            "SELECT connect_timeout_ms, lb_policy FROM clusters WHERE name='team-owned'"
        )
    assert row is not None and row["connect_timeout_ms"] == 1234 and row["lb_policy"] == "MAGLEV"
