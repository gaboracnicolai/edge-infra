"""FastAPI surface tests — drive endpoints through the ASGI transport."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import asyncpg
import nats.errors
import pytest


@pytest.fixture
def valid_spec() -> dict:
    return {
        "name": "my-service",
        "team": "platform",
        "host": "10.0.0.1",
        "port": 8080,
        "protocol": "HTTP",
        "auth_policy": "jwt",
    }


async def test_provision_valid(app_client, valid_spec):
    response = await app_client.post("/v1/services", json=valid_spec)
    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "PENDING"
    UUID(body["request_id"])
    assert "my-service" in body["message"]


async def test_provision_https_missing_tls_secret(app_client, valid_spec):
    valid_spec["protocol"] = "HTTPS"
    response = await app_client.post("/v1/services", json=valid_spec)
    assert response.status_code == 422


async def test_provision_invalid_name_uppercase(app_client, valid_spec):
    valid_spec["name"] = "MyService"
    response = await app_client.post("/v1/services", json=valid_spec)
    assert response.status_code == 422


async def test_provision_invalid_port(app_client, valid_spec):
    valid_spec["port"] = 99999
    response = await app_client.post("/v1/services", json=valid_spec)
    assert response.status_code == 422


async def test_provision_db_error(app_client, mock_pool, valid_spec):
    mock_pool.execute.side_effect = asyncpg.PostgresError("simulated db failure")
    response = await app_client.post("/v1/services", json=valid_spec)
    assert response.status_code == 500


async def test_provision_nats_error(app_client, mock_pool, mock_js, valid_spec):
    mock_js.publish.side_effect = nats.errors.TimeoutError()
    response = await app_client.post("/v1/services", json=valid_spec)
    assert response.status_code == 500
    # broker.provision must INSERT then, on publish failure, DELETE the row.
    assert mock_pool.execute.call_count == 2


async def test_deprovision(app_client):
    response = await app_client.delete("/v1/services/my-service")
    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "PENDING"
    assert "DELETE" in body["message"]
    assert "my-service" in body["message"]


async def test_get_request_found(app_client, mock_pool):
    request_id = uuid4()
    mock_pool.fetchrow = AsyncMock(
        return_value={
            "id": request_id,
            "operation": "CREATE",
            "status": "PENDING",
            "payload": "{}",
            "webhook_url": None,
            "error": None,
            "completed_at": None,
            "created_at": datetime.now(tz=UTC),
        }
    )
    response = await app_client.get(f"/v1/requests/{request_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "PENDING"
    assert body["id"] == str(request_id)


async def test_get_request_not_found(app_client, mock_pool):
    mock_pool.fetchrow = AsyncMock(return_value=None)
    response = await app_client.get(f"/v1/requests/{uuid4()}")
    assert response.status_code == 404


async def test_healthz(app_client):
    response = await app_client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"ok": True}
