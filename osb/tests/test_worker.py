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

    # The services upsert and the provision_requests COMPLETED transition both
    # run (order-independent: the translator's derived-row writes sit between
    # them inside the same transaction).
    sqls = [c.args[0] for c in mock_pool.execute.call_args_list]
    assert any(
        "INSERT INTO services" in s and "ON CONFLICT (team, name) DO UPDATE" in s for s in sqls
    )
    assert any("UPDATE provision_requests" in s and "'COMPLETED'" in s for s in sqls)


async def test_worker_delete_soft_deletes(mock_pool, cfg):
    request_id = str(uuid4())
    msg = make_msg(
        cfg.nats_subject_deprovision,
        {"team": "platform", "name": "api-svc"},
        headers={"Nats-Msg-Id": request_id},
    )

    await worker.process_message(msg, mock_pool, cfg)

    msg.ack.assert_awaited_once()
    msg.nak.assert_not_called()

    # Team-scoped soft-delete (the translator's derived-row deletes run first in
    # the same tx, so assert order-independently).
    sqls = [c.args[0] for c in mock_pool.execute.call_args_list]
    assert any(
        "UPDATE services SET deleted_at = NOW()" in s and "team = $1 AND name = $2" in s
        for s in sqls
    )


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


async def test_worker_malformed_request_id_acks_without_status(mock_pool, cfg, service_spec_dict):
    """A non-UUID Nats-Msg-Id is treated as absent: the services write still
    applies and the message is acked, but no provision_requests row is touched
    (a malformed id would otherwise blow up the UUID-typed queries and loop to
    max_deliver)."""
    msg = make_msg(
        cfg.nats_subject_provision,
        service_spec_dict,
        headers={"Nats-Msg-Id": "not-a-uuid"},
    )

    await worker.process_message(msg, mock_pool, cfg)

    msg.ack.assert_awaited_once()
    msg.nak.assert_not_called()

    # Only the services upsert ran — no provision_requests UPDATE / fetchrow,
    # since the id couldn't be correlated.
    executed_sqls = [call.args[0] for call in mock_pool.execute.call_args_list]
    assert any("INSERT INTO services" in sql for sql in executed_sqls)
    assert not any("provision_requests" in sql for sql in executed_sqls)
    mock_pool.fetchrow.assert_not_called()


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


async def test_sweep_once_deletes_terminal_rows(mock_pool, cfg):
    mock_pool.execute.return_value = "DELETE 7"

    result = await worker._sweep_once(cfg, mock_pool)

    assert result == "DELETE 7"
    sql = mock_pool.execute.call_args.args[0]
    assert "DELETE FROM provision_requests" in sql
    assert "status IN ('COMPLETED', 'FAILED')" in sql  # PENDING is never pruned
    assert "make_interval(days => $1)" in sql
    # retention window is passed as a bound parameter, not interpolated
    assert mock_pool.execute.call_args.args[1] == cfg.provision_retention_days


async def test_sweep_once_noop_when_disabled(mock_pool, cfg, monkeypatch):
    monkeypatch.setattr(cfg, "provision_retention_days", 0)

    result = await worker._sweep_once(cfg, mock_pool)

    assert result is None
    mock_pool.execute.assert_not_called()


async def test_run_retention_sweep_returns_when_disabled(mock_pool, cfg, monkeypatch):
    monkeypatch.setattr(cfg, "provision_retention_days", 0)

    # Must return promptly instead of entering the periodic loop.
    await asyncio.wait_for(worker.run_retention_sweep(cfg, mock_pool), timeout=1.0)
    mock_pool.execute.assert_not_called()
