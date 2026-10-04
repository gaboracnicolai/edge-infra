"""B28.197 — the provisioning freeze (osb_freeze) holds.

The first test drives the API with mocks. The second is the end-to-end proof
against a real Postgres AND a real NATS JetStream (skipped unless both
TEST_DATABASE_URL and TEST_NATS_URL are set): while frozen a POST is refused and
a spec queued before the freeze stays unapplied for longer than its whole
redelivery budget; unfreezing applies it.
"""

from __future__ import annotations

import asyncio
import os
import uuid

import asyncpg
import nats
import pytest
from httpx import ASGITransport, AsyncClient
from nats.js.api import RetentionPolicy, StorageType, StreamConfig

import broker
import worker
from config import Settings
from models import ServiceSpec

TEST_DB = os.getenv("TEST_DATABASE_URL")
TEST_NATS = os.getenv("TEST_NATS_URL")

SPEC = {"name": "frozen-svc", "team": "teama", "host": "10.0.0.9", "port": 8080, "protocol": "HTTP"}


async def test_api_refuses_to_queue_while_frozen(app_client, mock_pool, mock_js):
    mock_pool.fetchval.return_value = True

    post = await app_client.post("/v1/services", json={})  # refused before validation
    delete = await app_client.delete("/v1/services/frozen-svc")

    assert post.status_code == 503
    assert post.headers["retry-after"] == "60"
    assert delete.status_code == 503
    mock_js.publish.assert_not_awaited()
    mock_pool.execute.assert_not_awaited()  # no provision_requests row either


@pytest.mark.skipif(
    TEST_DB is None or TEST_NATS is None,
    reason="TEST_DATABASE_URL and TEST_NATS_URL not set (integration only)",
)
async def test_frozen_spec_stays_queued_then_applies_on_unfreeze(monkeypatch):
    import main

    # Shrink ack_wait so the wait below outlasts MAX_DELIVER deliveries: without
    # the hold the spec would be redelivered to exhaustion and dead-lettered.
    monkeypatch.setattr(worker, "ACK_WAIT_S", 1.0)
    monkeypatch.setattr(worker, "HOLD_BEAT_S", 0.2)
    monkeypatch.setattr(main.cfg, "allow_untenanted", True)
    suffix = uuid.uuid4().hex[:8]
    cfg = Settings(nats_stream=f"FREEZE{suffix}", nats_consumer_durable=f"freeze-{suffix}")

    pool = await asyncpg.create_pool(TEST_DB, min_size=1, max_size=4)
    nc = await nats.connect(TEST_NATS)
    js = nc.jetstream()
    await js.add_stream(
        StreamConfig(
            name=cfg.nats_stream,
            subjects=["edge.provision.*"],
            retention=RetentionPolicy.WORK_QUEUE,
            storage=StorageType.MEMORY,
        )
    )
    await pool.execute(
        "TRUNCATE services, provision_requests, routes, endpoints, clusters, "
        "gateways, dead_letter RESTART IDENTITY CASCADE"
    )
    task = None
    try:
        await pool.execute("UPDATE osb_freeze SET frozen = true, reason = 'test'")

        main.app.state.pool, main.app.state.js = pool, js
        async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://t") as c:
            refused = await c.post("/v1/services", json=SPEC)
        assert refused.status_code == 503

        # A spec that was queued before the freeze landed.
        queued = await broker.provision(ServiceSpec(**SPEC), pool, js, cfg, "teama")
        task = asyncio.create_task(worker.run_worker(cfg, pool, js))
        await asyncio.sleep(worker.ACK_WAIT_S * (worker.MAX_DELIVER + 2))

        assert await pool.fetchval("SELECT count(*) FROM services") == 0
        assert await pool.fetchval("SELECT count(*) FROM dead_letter") == 0
        status = "SELECT status FROM provision_requests WHERE id = $1"
        assert await pool.fetchval(status, queued.request_id) == "PENDING"
        info = await js.consumer_info(cfg.nats_stream, cfg.nats_consumer_durable)
        assert info.num_redelivered == 0, "the hold spent the spec's delivery budget"

        await pool.execute("UPDATE osb_freeze SET frozen = false, reason = NULL")
        for _ in range(50):
            if await pool.fetchval(status, queued.request_id) == "COMPLETED":
                break
            await asyncio.sleep(0.2)
        assert await pool.fetchval(status, queued.request_id) == "COMPLETED"
        row = await pool.fetchrow("SELECT team, host FROM services WHERE name = 'frozen-svc'")
        assert (row["team"], row["host"]) == ("teama", "10.0.0.9")
    finally:
        if task is not None:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        await pool.execute("UPDATE osb_freeze SET frozen = false, reason = NULL")
        await js.delete_stream(cfg.nats_stream)
        await nc.close()
        await pool.close()
