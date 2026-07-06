"""Broker-level tests — exercise broker.provision / broker.deprovision directly."""

from __future__ import annotations

import nats.errors
import pytest

import broker
from models import ServiceSpec


@pytest.fixture
def spec() -> ServiceSpec:
    return ServiceSpec(
        name="api-svc",
        team="platform",
        host="10.0.0.1",
        port=8080,
        protocol="HTTP",
    )


async def test_provision_db_before_nats(mock_pool, mock_js, cfg, spec):
    """The DB INSERT must complete before the NATS publish runs."""
    order: list[str] = []

    async def record_execute(*args, **kwargs):
        order.append("execute")
        return None

    async def record_publish(*args, **kwargs):
        order.append("publish")
        return None

    mock_pool.execute.side_effect = record_execute
    mock_js.publish.side_effect = record_publish

    await broker.provision(spec, mock_pool, mock_js, cfg, "platform")
    assert order == ["execute", "publish"]


async def test_provision_nats_failure_rolls_back(mock_pool, mock_js, cfg, spec):
    """If publish fails, the provision row must be deleted before re-raising."""
    mock_js.publish.side_effect = nats.errors.TimeoutError()

    with pytest.raises(nats.errors.TimeoutError):
        await broker.provision(spec, mock_pool, mock_js, cfg, "platform")

    assert mock_pool.execute.call_count == 2  # INSERT + compensating DELETE
    delete_call = mock_pool.execute.call_args_list[1]
    assert "DELETE FROM provision_requests" in delete_call.args[0]


async def test_deprovision_uses_delete_operation(mock_pool, mock_js, cfg):
    """broker.deprovision INSERTs operation='DELETE' and publishes to the deprovision subject."""
    response = await broker.deprovision("api-svc", mock_pool, mock_js, cfg, "platform")

    insert_call = mock_pool.execute.call_args_list[0]
    assert "'DELETE'" in insert_call.args[0]

    publish_call = mock_js.publish.call_args
    assert publish_call.args[0] == cfg.nats_subject_deprovision

    assert response.status == "PENDING"
    assert "DELETE" in response.message
