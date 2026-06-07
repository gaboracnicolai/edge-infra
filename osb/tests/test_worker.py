"""Tests for the NATS message processing loop."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock
from uuid import uuid4

import asyncpg
import pytest

import worker
from models import ServiceSpec


def make_msg(subject: str, data: dict | bytes, headers: dict | None = None) -> AsyncMock:
    """Build a NATS-message double with awaitable ack/nak."""
    msg = AsyncMock()
    msg.subject = subject
    msg.data = data if isinstance(data, bytes) else json.dumps(data).encode()
    msg.headers = headers or {}
    msg.ack = AsyncMock()
    msg.nak = AsyncMock()
    return msg


@pytest.fixture
def service_spec_dict() -> dict:
    return ServiceSpec(
        name="api-svc",
        team="platform",
        host="10.0.0.1",
        port=8080,
        protocol="HTTP",
    ).model_dump(mode="json")


async def test_worker_create_acks(mock_pool, cfg, service_spec_dict):
    request_id = str(uuid4())
    msg = make_msg(
        cfg.nats_subject_provision,
        service_spec_dict,
        headers={"Nats-Msg-Id": request_id},
    )

    await worker.process_message(msg, mock_pool, cfg)

    msg.ack.assert_awaited_once()
    msg.nak.assert_not_called()

    # First execute is the INSERT ... ON CONFLICT ... DO UPDATE on services.
    first_sql = mock_pool.execute.call_args_list[0].args[0]
    assert "INSERT INTO services" in first_sql
    assert "ON CONFLICT (name) DO UPDATE" in first_sql

    # Then provision_requests transitions to COMPLETED.
    second_sql = mock_pool.execute.call_args_list[1].args[0]
    assert "UPDATE provision_requests" in second_sql
    assert "'COMPLETED'" in second_sql


async def test_worker_delete_soft_deletes(mock_pool, cfg):
    request_id = str(uuid4())
    msg = make_msg(
        cfg.nats_subject_deprovision,
        {"name": "api-svc"},
        headers={"Nats-Msg-Id": request_id},
    )

    await worker.process_message(msg, mock_pool, cfg)

    msg.ack.assert_awaited_once()
    msg.nak.assert_not_called()

    first_sql = mock_pool.execute.call_args_list[0].args[0]
    assert "UPDATE services SET deleted_at = NOW()" in first_sql


async def test_worker_db_error_naks(mock_pool, cfg, service_spec_dict):
    request_id = str(uuid4())
    msg = make_msg(
        cfg.nats_subject_provision,
        service_spec_dict,
        headers={"Nats-Msg-Id": request_id},
    )
    # First call (INSERT services) fails; the FAILED-status update is best-effort
    # so we let the second call succeed.
    mock_pool.execute.side_effect = [asyncpg.PostgresError("boom"), None]

    await worker.process_message(msg, mock_pool, cfg)

    msg.nak.assert_awaited_once_with(delay=30)
    msg.ack.assert_not_called()


async def test_worker_no_webhook_when_url_none(mock_pool, cfg, service_spec_dict, monkeypatch):
    request_id = str(uuid4())
    msg = make_msg(
        cfg.nats_subject_provision,
        service_spec_dict,
        headers={"Nats-Msg-Id": request_id},
    )
    mock_pool.fetchrow.return_value = {"webhook_url": None}

    called = {"deliver": False}

    async def fake_deliver(*args, **kwargs):
        called["deliver"] = True

    monkeypatch.setattr(worker.webhook, "deliver", fake_deliver)

    await worker.process_message(msg, mock_pool, cfg)

    assert called["deliver"] is False
    msg.ack.assert_awaited_once()


async def test_worker_duplicate_is_idempotent(mock_pool, cfg, service_spec_dict):
    request_id = str(uuid4())
    msg1 = make_msg(
        cfg.nats_subject_provision,
        service_spec_dict,
        headers={"Nats-Msg-Id": request_id},
    )
    msg2 = make_msg(
        cfg.nats_subject_provision,
        service_spec_dict,
        headers={"Nats-Msg-Id": request_id},
    )

    await worker.process_message(msg1, mock_pool, cfg)
    await worker.process_message(msg2, mock_pool, cfg)

    msg1.ack.assert_awaited_once()
    msg2.ack.assert_awaited_once()
    msg1.nak.assert_not_called()
    msg2.nak.assert_not_called()

    # Two invocations should each issue the same INSERT ... ON CONFLICT DO UPDATE
    # (no uniqueness violation thanks to upsert semantics).
    insert_sqls = [
        call.args[0]
        for call in mock_pool.execute.call_args_list
        if "INSERT INTO services" in call.args[0]
    ]
    assert len(insert_sqls) == 2


async def test_worker_webhook_does_not_block_ack(mock_pool, cfg, service_spec_dict, monkeypatch):
    """A slow webhook must not delay the ack.

    Regression: delivery used to be awaited inline before ``msg.ack()``, so a
    target slow enough to cross ``ack_wait`` triggered a JetStream redelivery
    storm (duplicate service writes + repeat webhooks). Delivery now runs as a
    detached task scheduled *after* the ack.
    """
    request_id = str(uuid4())
    msg = make_msg(
        cfg.nats_subject_provision,
        service_spec_dict,
        headers={"Nats-Msg-Id": request_id},
    )
    mock_pool.fetchrow.return_value = {"webhook_url": "https://hooks.example.test/edge"}

    started = asyncio.Event()
    release = asyncio.Event()
    captured: dict = {}

    async def blocking_deliver(url, payload, cfg):
        captured["url"] = url
        captured["payload"] = payload
        started.set()
        await release.wait()  # hold the "delivery" open well past ack_wait

    monkeypatch.setattr(worker.webhook, "deliver", blocking_deliver)

    # Before the fix this awaited blocking_deliver inline and never returned,
    # so wait_for would time out.
    await asyncio.wait_for(worker.process_message(msg, mock_pool, cfg), timeout=1.0)

    # Acked exactly once, with the webhook still in flight (not nak'd).
    msg.ack.assert_awaited_once()
    msg.nak.assert_not_called()

    # Delivery was scheduled (decoupled, not dropped) and is running detached.
    await asyncio.wait_for(started.wait(), timeout=1.0)
    assert worker._webhook_tasks  # task is held (no GC mid-flight)
    assert captured["url"] == "https://hooks.example.test/edge"
    assert captured["payload"]["request_id"] == request_id
    assert captured["payload"]["status"] == "COMPLETED"
    assert captured["payload"]["service"] == "api-svc"

    # Let the detached task finish so it doesn't outlive the test.
    release.set()
    for task in list(worker._webhook_tasks):
        await task
